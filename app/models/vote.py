"""
Vote model for managing encrypted votes
"""

import os
import json
from app import encryption_context

class VoteModel:
    """Model for handling votes and results"""
    
    def __init__(self, votes_dir, results_dir):
        self.votes_dir = votes_dir
        self.results_dir = results_dir
    
    def serialize_ciphertext(self, ciphertext):
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
    
    def deserialize_ciphertext(self, serialized_data):
        """
        Deserialize a ciphertext from storage format back to a TFHECiphertext object
        """
        import numpy as np
        from tfhe_lib import TFHECiphertext
        
        cipher0 = np.array(serialized_data['cipher0'], dtype=np.int64)
        cipher1 = np.array(serialized_data['cipher1'], dtype=np.int64)
        
        # Create a new ciphertext object
        return TFHECiphertext((cipher0, cipher1), encryption_context)
    
    def save_vote(self, election_id, voter_id, selected_candidate, candidates):
        """Save an encrypted vote"""
        vote_file = os.path.join(self.votes_dir, f"vote_{election_id}_{voter_id}.json")
        
        # Create encrypted votes (1 for selected, 0 for others)
        encrypted_votes = {}
        for candidate in candidates:
            if candidate == selected_candidate:
                # Encrypt a '1' for the selected candidate
                encrypted_vote = encryption_context.encrypt_bit(1)
            else:
                # Encrypt a '0' for all other candidates
                encrypted_vote = encryption_context.encrypt_bit(0)
            
            # Serialize the encrypted vote
            encrypted_votes[candidate] = self.serialize_ciphertext(encrypted_vote)
        
        # Save the encrypted vote
        with open(vote_file, 'w') as f:
            json.dump(encrypted_votes, f, indent=2)
        
        return True
    
    def has_voted(self, election_id, voter_id):
        """Check if a voter has already voted in an election"""
        vote_file = os.path.join(self.votes_dir, f"vote_{election_id}_{voter_id}.json")
        return os.path.exists(vote_file)
    
    def count_votes(self, election_id, election):
        """
        Count votes for a specific election using homomorphic encryption
        """
        if not election:
            return None

        # Initialize result containers for each candidate
        candidates = election['candidates']
        encrypted_results = {candidate: None for candidate in candidates}
        
        # Get all vote files for this election
        vote_files = [f for f in os.listdir(self.votes_dir) 
                     if f.startswith(f"vote_{election_id}_") and f.endswith(".json")]
        
        vote_count = 0
        
        # Process each vote
        for vote_file in vote_files:
            vote_count += 1
            with open(os.path.join(self.votes_dir, vote_file), 'r') as f:
                vote_data = json.load(f)
            
            # For each candidate, combine their encrypted vote with current tally
            for candidate in candidates:
                # Get the encrypted vote for this candidate (0 or 1)
                vote_cipher_data = vote_data.get(candidate, None)
                if vote_cipher_data:
                    # Deserialize the ciphertext
                    vote_cipher = self.deserialize_ciphertext(vote_cipher_data)
                    
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
        from datetime import datetime
        result_data = {
            'election_id': election_id,
            'election_name': election['name'],
            'vote_count': vote_count,
            'results': results,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        result_file = os.path.join(self.results_dir, f"result_{election_id}.json")
        with open(result_file, 'w') as f:
            json.dump(result_data, f, indent=2)
        
        return result_data
    
    def get_results(self, election_id):
        """Get results for an election if they exist"""
        result_file = os.path.join(self.results_dir, f"result_{election_id}.json")
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                return json.load(f)
        return None