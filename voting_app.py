"""
Secure Voting Application using TFHE Encryption

This Flask application provides a web interface for a secure voting system
backed by the TFHE homomorphic encryption scheme.
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import json
import uuid
from datetime import datetime
from tfhe_lib import TFHEContext, homomorphic_or

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Directory for storing encrypted votes
VOTES_DIR = "votes"
RESULTS_DIR = "results"
ELECTIONS_FILE = "elections.json"

# Ensure directories exist
os.makedirs(VOTES_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# Initialize a global encryption context
# Note: In a real application, you would need to securely manage keys
encryption_context = TFHEContext(polynomial_size=32).generate_keys()


def load_elections():
    """Load election data from file"""
    if os.path.exists(ELECTIONS_FILE):
        with open(ELECTIONS_FILE, 'r') as f:
            return json.load(f)
    return []


def save_elections(elections):
    """Save election data to file"""
    with open(ELECTIONS_FILE, 'w') as f:
        json.dump(elections, f, indent=2)


def get_election(election_id):
    """Get a specific election by ID"""
    elections = load_elections()
    for election in elections:
        if election['id'] == election_id:
            return election
    return None


def count_votes(election_id):
    """
    Count votes for a specific election using homomorphic encryption
    """
    election = get_election(election_id)
    if not election:
        return None

    # Initialize result containers for each candidate
    candidates = election['candidates']
    encrypted_results = {candidate: None for candidate in candidates}
    
    # Get all vote files for this election
    vote_files = [f for f in os.listdir(VOTES_DIR) 
                 if f.startswith(f"vote_{election_id}_") and f.endswith(".json")]
    
    vote_count = 0
    
    # Process each vote
    for vote_file in vote_files:
        vote_count += 1
        with open(os.path.join(VOTES_DIR, vote_file), 'r') as f:
            vote_data = json.load(f)
        
        # For each candidate, combine their encrypted vote with current tally
        for candidate in candidates:
            # Get the encrypted vote for this candidate (0 or 1)
            vote_cipher_data = vote_data.get(candidate, None)
            if vote_cipher_data:
                # Deserialize the ciphertext
                vote_cipher = deserialize_ciphertext(vote_cipher_data)
                
                # Update the running total
                if encrypted_results[candidate] is None:
                    encrypted_results[candidate] = vote_cipher
                else:
                    # Homomorphically add the new vote to the running total
                    encrypted_results[candidate] = encrypted_results[candidate] + vote_cipher
    
    # Decrypt the final results
    results = {}
    for candidate, encrypted_count in encrypted_results.items():
        if encrypted_count is not None:
            # Decrypt to get the count
            count = encryption_context.decrypt_to_integer(encrypted_count)
            results[candidate] = count
        else:
            results[candidate] = 0
    
    # Save the results
    result_data = {
        'election_id': election_id,
        'election_name': election['name'],
        'vote_count': vote_count,
        'results': results,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    result_file = os.path.join(RESULTS_DIR, f"result_{election_id}.json")
    with open(result_file, 'w') as f:
        json.dump(result_data, f, indent=2)
    
    return result_data


def serialize_ciphertext(ciphertext):
    """
    Serialize a TFHECiphertext object for storage
    Note: This is a simplified version, real implementations would need proper serialization
    """
    # Extract the raw data to serialize
    cipher0 = ciphertext.raw_ciphertext[0].tolist()
    cipher1 = ciphertext.raw_ciphertext[1].tolist()
    
    return {
        'cipher0': cipher0,
        'cipher1': cipher1
    }


def deserialize_ciphertext(serialized_data):
    """
    Deserialize a ciphertext from storage format back to a TFHECiphertext object
    """
    import numpy as np
    from tfhe_lib import TFHECiphertext
    
    cipher0 = np.array(serialized_data['cipher0'], dtype=np.int64)
    cipher1 = np.array(serialized_data['cipher1'], dtype=np.int64)
    
    # Create a new ciphertext object
    return TFHECiphertext((cipher0, cipher1), encryption_context)


@app.route('/')
def home():
    """Home page shows list of elections"""
    elections = load_elections()
    return render_template('home.html', elections=elections)


@app.route('/create_election', methods=['GET', 'POST'])
def create_election():
    """Create a new election"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        candidates = [c.strip() for c in request.form.get('candidates').split(',')]
        
        if not name or not candidates:
            flash('Please fill in all required fields')
            return redirect(url_for('create_election'))
        
        election_id = str(uuid.uuid4())
        
        election = {
            'id': election_id,
            'name': name,
            'description': description,
            'candidates': candidates,
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'active': True
        }
        
        elections = load_elections()
        elections.append(election)
        save_elections(elections)
        
        flash('Election created successfully')
        return redirect(url_for('home'))
    
    return render_template('create_election.html')


@app.route('/election/<election_id>')
def view_election(election_id):
    """View a specific election"""
    election = get_election(election_id)
    if not election:
        flash('Election not found')
        return redirect(url_for('home'))
    
    # Check if results exist
    result_file = os.path.join(RESULTS_DIR, f"result_{election_id}.json")
    results = None
    if os.path.exists(result_file):
        with open(result_file, 'r') as f:
            results = json.load(f)
    
    return render_template('view_election.html', election=election, results=results)


@app.route('/vote/<election_id>', methods=['GET', 'POST'])
def vote(election_id):
    """Cast a vote in a specific election"""
    election = get_election(election_id)
    if not election:
        flash('Election not found')
        return redirect(url_for('home'))
    
    if not election['active']:
        flash('This election is no longer active')
        return redirect(url_for('view_election', election_id=election_id))
    
    if request.method == 'POST':
        # Check if user has already voted
        voter_id = session.get('voter_id', str(uuid.uuid4()))
        session['voter_id'] = voter_id
        
        vote_file = os.path.join(VOTES_DIR, f"vote_{election_id}_{voter_id}.json")
        if os.path.exists(vote_file):
            flash('You have already voted in this election')
            return redirect(url_for('view_election', election_id=election_id))
        
        # Get the selected candidate
        selected_candidate = request.form.get('candidate')
        if not selected_candidate or selected_candidate not in election['candidates']:
            flash('Please select a valid candidate')
            return redirect(url_for('vote', election_id=election_id))
        
        # Create encrypted votes (1 for selected, 0 for others)
        encrypted_votes = {}
        for candidate in election['candidates']:
            if candidate == selected_candidate:
                # Encrypt a '1' for the selected candidate
                encrypted_vote = encryption_context.encrypt_bit(1)
            else:
                # Encrypt a '0' for all other candidates
                encrypted_vote = encryption_context.encrypt_bit(0)
            
            # Serialize the encrypted vote
            encrypted_votes[candidate] = serialize_ciphertext(encrypted_vote)
        
        # Save the encrypted vote
        with open(vote_file, 'w') as f:
            json.dump(encrypted_votes, f, indent=2)
        
        flash('Your vote has been cast successfully')
        return redirect(url_for('view_election', election_id=election_id))
    
    return render_template('vote.html', election=election)


@app.route('/close_election/<election_id>')
def close_election(election_id):
    """Close an election and count the votes"""
    election = get_election(election_id)
    if not election:
        flash('Election not found')
        return redirect(url_for('home'))
    
    # Update election status
    elections = load_elections()
    for e in elections:
        if e['id'] == election_id:
            e['active'] = False
    save_elections(elections)
    
    # Count votes
    results = count_votes(election_id)
    if results:
        flash('Election closed and votes counted successfully')
    else:
        flash('Error counting votes')
    
    return redirect(url_for('view_election', election_id=election_id))


@app.route('/results/<election_id>')
def view_results(election_id):
    """View detailed results for a specific election"""
    election = get_election(election_id)
    if not election:
        flash('Election not found')
        return redirect(url_for('home'))
    
    # Check if results exist
    result_file = os.path.join(RESULTS_DIR, f"result_{election_id}.json")
    if not os.path.exists(result_file):
        flash('No results available for this election')
        return redirect(url_for('view_election', election_id=election_id))
    
    with open(result_file, 'r') as f:
        results = json.load(f)
    
    return render_template('results.html', election=election, results=results)


if __name__ == '__main__':
    # Create template files if they don't exist
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    os.makedirs(template_dir, exist_ok=True)
    
    # Create template files
    templates = {
        'home.html': """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Voting System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        body { padding-top: 2rem; }
        .election-list { margin-top: 2rem; }
    </style>
</head>
<body>
    <div class="container">
        <header class="mb-4">
            <h1>Post-Quantum Secure Voting System</h1>
            <p class="lead">A voting application backed by TFHE homomorphic encryption</p>
        </header>
        
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="d-flex justify-content-between mb-4">
            <h2>Active Elections</h2>
            <a href="{{ url_for('create_election') }}" class="btn btn-primary">Create New Election</a>
        </div>
        
        <div class="election-list">
            {% if elections %}
                <div class="list-group">
                    {% for election in elections %}
                        <a href="{{ url_for('view_election', election_id=election.id) }}" class="list-group-item list-group-item-action">
                            <div class="d-flex w-100 justify-content-between">
                                <h5 class="mb-1">{{ election.name }}</h5>
                                <small>Created: {{ election.created_at }}</small>
                            </div>
                            <p class="mb-1">{{ election.description }}</p>
                            <small>Status: {% if election.active %}Active{% else %}Closed{% endif %}</small>
                        </a>
                    {% endfor %}
                </div>
            {% else %}
                <div class="alert alert-warning">No elections have been created yet.</div>
            {% endif %}
        </div>
    </div>
    
    <footer class="container mt-5 pt-3 border-top text-center text-muted">
        <p>Secure Voting System powered by Post-Quantum Cryptography (TFHE)</p>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        """,
        
        'create_election.html': """
<!DOCTYPE html>
<html>
<head>
    <title>Create Election - Secure Voting System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        body { padding-top: 2rem; }
    </style>
</head>
<body>
    <div class="container">
        <header class="mb-4">
            <h1>Create a New Election</h1>
            <a href="{{ url_for('home') }}" class="btn btn-outline-secondary">Back to Home</a>
        </header>
        
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="card">
            <div class="card-body">
                <form method="post">
                    <div class="mb-3">
                        <label for="name" class="form-label">Election Name</label>
                        <input type="text" class="form-control" id="name" name="name" required>
                    </div>
                    
                    <div class="mb-3">
                        <label for="description" class="form-label">Description</label>
                        <textarea class="form-control" id="description" name="description" rows="3"></textarea>
                    </div>
                    
                    <div class="mb-3">
                        <label for="candidates" class="form-label">Candidates</label>
                        <input type="text" class="form-control" id="candidates" name="candidates" 
                               placeholder="Enter candidates separated by commas" required>
                        <div class="form-text">Example: Alice, Bob, Charlie</div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Create Election</button>
                </form>
            </div>
        </div>
    </div>
    
    <footer class="container mt-5 pt-3 border-top text-center text-muted">
        <p>Secure Voting System powered by Post-Quantum Cryptography (TFHE)</p>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        """,
        
        'view_election.html': """
<!DOCTYPE html>
<html>
<head>
    <title>{{ election.name }} - Secure Voting System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        body { padding-top: 2rem; }
        .candidate-list { margin-top: 1.5rem; }
    </style>
</head>
<body>
    <div class="container">
        <header class="mb-4">
            <h1>{{ election.name }}</h1>
            <a href="{{ url_for('home') }}" class="btn btn-outline-secondary">Back to Home</a>
        </header>
        
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="card mb-4">
            <div class="card-body">
                <h5 class="card-title">Election Details</h5>
                <p class="card-text">{{ election.description }}</p>
                <p><strong>Created:</strong> {{ election.created_at }}</p>
                <p><strong>Status:</strong> {% if election.active %}Active{% else %}Closed{% endif %}</p>
                
                <div class="candidate-list">
                    <h6>Candidates:</h6>
                    <ul class="list-group">
                        {% for candidate in election.candidates %}
                            <li class="list-group-item">{{ candidate }}</li>
                        {% endfor %}
                    </ul>
                </div>
                
                <div class="mt-4">
                    {% if election.active %}
                        <a href="{{ url_for('vote', election_id=election.id) }}" class="btn btn-primary me-2">Cast Your Vote</a>
                        <a href="{{ url_for('close_election', election_id=election.id) }}" class="btn btn-warning">Close Election & Count Votes</a>
                    {% else %}
                        <a href="{{ url_for('view_results', election_id=election.id) }}" class="btn btn-info">View Detailed Results</a>
                    {% endif %}
                </div>
            </div>
        </div>
        
        {% if results %}
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Election Results</h5>
                    <p><strong>Total Votes:</strong> {{ results.vote_count }}</p>
                    
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Candidate</th>
                                <th>Votes</th>
                                <th>Percentage</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for candidate, votes in results.results.items() %}
                                <tr>
                                    <td>{{ candidate }}</td>
                                    <td>{{ votes }}</td>
                                    <td>{{ "%.2f"|format(votes / results.vote_count * 100) }}%</td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    
                    <small class="text-muted">Results calculated at: {{ results.timestamp }}</small>
                </div>
            </div>
        {% endif %}
    </div>
    
    <footer class="container mt-5 pt-3 border-top text-center text-muted">
        <p>Secure Voting System powered by Post-Quantum Cryptography (TFHE)</p>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        """,
        
        'vote.html': """
<!DOCTYPE html>
<html>
<head>
    <title>Vote - {{ election.name }}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        body { padding-top: 2rem; }
        .candidate-card { 
            cursor: pointer; 
            transition: all 0.2s;
            border: 2px solid transparent;
        }
        .candidate-card:hover { 
            transform: translateY(-5px); 
            box-shadow: 0 10px 20px rgba(0,0,0,0.1); 
        }
        input[type="radio"] { 
            position: absolute;
            opacity: 0;
        }
        input[type="radio"]:checked + .candidate-card { 
            border-color: #0d6efd; 
            background-color: #f0f7ff;
            box-shadow: 0 0 0 3px rgba(13, 110, 253, 0.25);
        }
        .selected-indicator {
            display: none;
            position: absolute;
            top: 10px;
            right: 10px;
            color: #0d6efd;
            font-size: 1.5rem;
        }
        input[type="radio"]:checked + .candidate-card .selected-indicator {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="mb-4">
            <h1>Cast Your Vote: {{ election.name }}</h1>
            <a href="{{ url_for('view_election', election_id=election.id) }}" class="btn btn-outline-secondary">Back to Election</a>
        </header>
        
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="alert alert-info">
            <p><strong>Important:</strong> Your vote will be encrypted using post-quantum secure homomorphic encryption. 
            This means your vote remains private, but can still be counted in the final tally.</p>
        </div>
        
        <form method="post">
            <h5 class="mb-3">Select a candidate:</h5>
            
            <div class="row row-cols-1 row-cols-md-3 g-4 mb-4">
                {% for candidate in election.candidates %}
                    <div class="col">
                        <div class="position-relative">
                            <input type="radio" name="candidate" id="candidate-{{ loop.index }}" value="{{ candidate }}" required>
                            <label for="candidate-{{ loop.index }}" class="candidate-card card h-100 w-100">
                                <div class="selected-indicator">✓</div>
                                <div class="card-body text-center">
                                    <h5 class="card-title">{{ candidate }}</h5>
                                    <p class="card-text text-muted">Candidate #{{ loop.index }}</p>
                                </div>
                            </label>
                        </div>
                    </div>
                {% endfor %}
            </div>
            
            <div class="alert alert-warning">
                <p><strong>Warning:</strong> Once submitted, your vote cannot be changed. Please review your selection carefully.</p>
            </div>
            
            <button type="submit" class="btn btn-primary btn-lg">Submit Your Vote</button>
        </form>
    </div>
    
    <footer class="container mt-5 pt-3 border-top text-center text-muted">
        <p>Secure Voting System powered by Post-Quantum Cryptography (TFHE)</p>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Add click feedback for candidates
        document.addEventListener('DOMContentLoaded', function() {
            const radioInputs = document.querySelectorAll('input[type="radio"][name="candidate"]');
            
            radioInputs.forEach(input => {
                input.addEventListener('change', function() {
                    // Add visual feedback when selection changes
                    document.querySelectorAll('.candidate-card').forEach(card => {
                        card.classList.remove('selected');
                    });
                    
                    if (this.checked) {
                        // Show a message about which candidate is selected
                        const candidateName = this.value;
                        console.log('Selected candidate:', candidateName);
                    }
                });
            });
        });
    </script>
</body>
</html>
        """,
        
        'results.html': """
<!DOCTYPE html>
<html>
<head>
    <title>Results - {{ election.name }}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { padding-top: 2rem; }
        .results-container { margin-top: 2rem; }
    </style>
</head>
<body>
    <div class="container">
        <header class="mb-4">
            <h1>Election Results: {{ election.name }}</h1>
            <a href="{{ url_for('view_election', election_id=election.id) }}" class="btn btn-outline-secondary">Back to Election</a>
        </header>
        
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="card mb-4">
            <div class="card-body">
                <h5 class="card-title">Summary</h5>
                <p><strong>Total Votes:</strong> {{ results.vote_count }}</p>
                <p><strong>Calculated at:</strong> {{ results.timestamp }}</p>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Vote Distribution</h5>
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Candidate</th>
                                    <th>Votes</th>
                                    <th>Percentage</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for candidate, votes in results.results.items() %}
                                    <tr>
                                        <td>{{ candidate }}</td>
                                        <td>{{ votes }}</td>
                                        <td>{{ "%.2f"|format(votes / results.vote_count * 100) }}%</td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Results Chart</h5>
                        <canvas id="resultsChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card mt-4">
            <div class="card-body">
                <h5 class="card-title">About Encrypted Voting</h5>
                <p>These results were calculated using homomorphic encryption technology, which allows votes to be counted without ever being decrypted individually. This preserves voter privacy while ensuring accurate results.</p>
                <p><strong>Post-Quantum Security:</strong> The TFHE encryption used in this system is designed to be secure against both classical and quantum computers.</p>
            </div>
        </div>
    </div>
    
    <footer class="container mt-5 pt-3 border-top text-center text-muted">
        <p>Secure Voting System powered by Post-Quantum Cryptography (TFHE)</p>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Create chart for results
        document.addEventListener('DOMContentLoaded', function() {
            const ctx = document.getElementById('resultsChart').getContext('2d');
            
            const candidates = [{% for candidate in results.results.keys() %}'{{ candidate }}',{% endfor %}];
            const votes = [{% for votes in results.results.values() %}{{ votes }},{% endfor %}];
            
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: candidates,
                    datasets: [{
                        data: votes,
                        backgroundColor: [
                            'rgba(54, 162, 235, 0.6)',
                            'rgba(255, 99, 132, 0.6)',
                            'rgba(255, 206, 86, 0.6)',
                            'rgba(75, 192, 192, 0.6)',
                            'rgba(153, 102, 255, 0.6)',
                            'rgba(255, 159, 64, 0.6)'
                        ],
                        borderColor: [
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 99, 132, 1)',
                            'rgba(255, 206, 86, 1)',
                            'rgba(75, 192, 192, 1)',
                            'rgba(153, 102, 255, 1)',
                            'rgba(255, 159, 64, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'right',
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = Math.round((value / total) * 100);
                                    return `${label}: ${value} votes (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        });
    </script>
</body>
</html>
        """
    }
    
    for filename, content in templates.items():
        file_path = os.path.join(template_dir, filename)
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write(content.strip())
    
    app.run(debug=True)