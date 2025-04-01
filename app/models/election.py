"""
Election model for managing election data
"""

import os
import json
from datetime import datetime
import uuid

class ElectionModel:
    """Model for handling election data"""
    
    def __init__(self, elections_file):
        self.elections_file = elections_file
    
    def load_elections(self):
        """Load election data from file"""
        if os.path.exists(self.elections_file):
            with open(self.elections_file, 'r') as f:
                return json.load(f)
        return []
    
    def save_elections(self, elections):
        """Save election data to file"""
        with open(self.elections_file, 'w') as f:
            json.dump(elections, f, indent=2)
    
    def get_election(self, election_id):
        """Get a specific election by ID"""
        elections = self.load_elections()
        for election in elections:
            if election['id'] == election_id:
                return election
        return None
    
    def create_election(self, name, description, candidates):
        """Create a new election"""
        election_id = str(uuid.uuid4())
        
        election = {
            'id': election_id,
            'name': name,
            'description': description,
            'candidates': candidates,
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'active': True
        }
        
        elections = self.load_elections()
        elections.append(election)
        self.save_elections(elections)
        
        return election
    
    def close_election(self, election_id):
        """Close an election"""
        elections = self.load_elections()
        success = False
        
        for election in elections:
            if election['id'] == election_id:
                election['active'] = False
                success = True
                break
                
        if success:
            self.save_elections(elections)
            
        return success