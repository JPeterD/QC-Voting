"""
Main routes for the application
"""

from flask import Blueprint, render_template, session, current_app
import uuid
import os
from app.models.election import ElectionModel
from app.models.vote import VoteModel

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    """Home page shows list of elections"""
    election_model = ElectionModel(current_app.config['ELECTIONS_FILE'])
    vote_model = VoteModel(current_app.config['VOTES_DIR'], current_app.config['RESULTS_DIR'])
    
    elections = election_model.load_elections()
    
    # Check which elections the current user has voted in
    voter_id = session.get('voter_id', str(uuid.uuid4()))
    session['voter_id'] = voter_id
    
    voted_elections = set()
    for election in elections:
        if vote_model.has_voted(election['id'], voter_id):
            voted_elections.add(election['id'])
    
    return render_template('home.html', elections=elections, voted_elections=voted_elections)