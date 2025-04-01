"""
Routes for vote management
"""

from flask import Blueprint, render_template, request, redirect, url_for, current_app, flash, session
import uuid
import requests
from app.models.election import ElectionModel
from app.models.vote import VoteModel

votes_bp = Blueprint('votes', __name__)

def verify_recaptcha(recaptcha_response):
    """Verify reCAPTCHA response with Google's API"""
    if not recaptcha_response:
        return False
    
    # Verify with Google's reCAPTCHA API
    data = {
        'secret': current_app.config['RECAPTCHA_SECRET_KEY'],
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = response.json()
    
    return result.get('success', False)


@votes_bp.route('/vote/<election_id>', methods=['GET', 'POST'])
def vote(election_id):
    """Cast a vote in a specific election"""
    election_model = ElectionModel(current_app.config['ELECTIONS_FILE'])
    vote_model = VoteModel(current_app.config['VOTES_DIR'], current_app.config['RESULTS_DIR'])
    
    election = election_model.get_election(election_id)
    if not election:
        flash('Election not found')
        return redirect(url_for('main.home'))
    
    if not election['active']:
        flash('This election is no longer active')
        return redirect(url_for('elections.view_election', election_id=election_id))
    
    # Check if user has already voted
    voter_id = session.get('voter_id', str(uuid.uuid4()))
    session['voter_id'] = voter_id
    
    if vote_model.has_voted(election_id, voter_id):
        flash('You have already voted in this election')
        return redirect(url_for('elections.view_election', election_id=election_id))
    
    if request.method == 'POST':
        # Verify CAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_response):
            flash('CAPTCHA verification failed. Please try again.')
            return render_template('vote.html', election=election, 
                                  recaptcha_site_key=current_app.config['RECAPTCHA_SITE_KEY'])
        
        # Get the selected candidate
        selected_candidate = request.form.get('candidate')
        if not selected_candidate or selected_candidate not in election['candidates']:
            flash('Please select a valid candidate')
            return redirect(url_for('votes.vote', election_id=election_id))
        
        # Save the vote
        success = vote_model.save_vote(election_id, voter_id, selected_candidate, election['candidates'])
        
        if success:
            flash('Your vote has been cast successfully')
            return redirect(url_for('elections.view_election', election_id=election_id))
        else:
            flash('Error casting vote')
            return redirect(url_for('votes.vote', election_id=election_id))
    
    return render_template('vote.html', election=election, 
                          recaptcha_site_key=current_app.config['RECAPTCHA_SITE_KEY'])