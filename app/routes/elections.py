"""
Routes for election management
"""

from flask import Blueprint, render_template, request, redirect, url_for, current_app, flash, session
import os
import uuid
from app.models.admin import admin_required
from app.models.election import ElectionModel
from app.models.vote import VoteModel

elections_bp = Blueprint('elections', __name__)

@elections_bp.route('/create_election', methods=['GET', 'POST'])
@admin_required
def create_election():
    """Create a new election (admin only)"""
    election_model = ElectionModel(current_app.config['ELECTIONS_FILE'])
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        candidates = [c.strip() for c in request.form.get('candidates').split(',')]
        
        if not name or not candidates:
            flash('Please fill in all required fields')
            return redirect(url_for('elections.create_election'))
        
        election = election_model.create_election(name, description, candidates)
        
        flash('Election created successfully')
        return redirect(url_for('main.home'))
    
    return render_template('create_election.html')


@elections_bp.route('/election/<election_id>')
def view_election(election_id):
    """View a specific election"""
    election_model = ElectionModel(current_app.config['ELECTIONS_FILE'])
    vote_model = VoteModel(current_app.config['VOTES_DIR'], current_app.config['RESULTS_DIR'])
    
    election = election_model.get_election(election_id)
    if not election:
        flash('Election not found')
        return redirect(url_for('main.home'))
    
    # Check if results exist
    results = vote_model.get_results(election_id)
    
    # Check if the current user has already voted
    voter_id = session.get('voter_id', str(uuid.uuid4()))
    session['voter_id'] = voter_id
    has_voted = vote_model.has_voted(election_id, voter_id)
    
    return render_template('view_election.html', election=election, results=results, has_voted=has_voted)


@elections_bp.route('/close_election/<election_id>')
@admin_required
def close_election(election_id):
    """Close an election and count the votes (admin only)"""
    election_model = ElectionModel(current_app.config['ELECTIONS_FILE'])
    vote_model = VoteModel(current_app.config['VOTES_DIR'], current_app.config['RESULTS_DIR'])
    
    election = election_model.get_election(election_id)
    if not election:
        flash('Election not found')
        return redirect(url_for('main.home'))
    
    # Update election status
    success = election_model.close_election(election_id)
    
    # Count votes
    if success:
        results = vote_model.count_votes(election_id, election)
        if results:
            flash('Election closed and votes counted successfully')
        else:
            flash('Error counting votes')
    else:
        flash('Error closing election')
    
    return redirect(url_for('elections.view_election', election_id=election_id))


@elections_bp.route('/results/<election_id>')
def view_results(election_id):
    """View detailed results for a specific election"""
    election_model = ElectionModel(current_app.config['ELECTIONS_FILE'])
    vote_model = VoteModel(current_app.config['VOTES_DIR'], current_app.config['RESULTS_DIR'])
    
    election = election_model.get_election(election_id)
    if not election:
        flash('Election not found')
        return redirect(url_for('main.home'))
    
    # Check if results exist
    results = vote_model.get_results(election_id)
    if not results:
        flash('No results available for this election')
        return redirect(url_for('elections.view_election', election_id=election_id))
    
    return render_template('results.html', election=election, results=results)