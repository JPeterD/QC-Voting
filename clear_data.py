import os
import json
import glob

def clear_elections(elections_file='elections.json'):
    if os.path.exists(elections_file):
        with open(elections_file, 'w') as f:
            json.dump([], f, indent=2)
        print(f"Cleared {elections_file}")
    else:
        print(f"{elections_file} does not exist.")

def clear_directory(directory):
    if os.path.exists(directory):
        files = glob.glob(os.path.join(directory, '*'))
        for file_path in files:
            try:
                os.remove(file_path)
                print(f"Deleted {file_path}")
            except Exception as e:
                print(f"Failed to delete {file_path}: {e}")
    else:
        print(f"{directory} does not exist.")

if __name__ == "__main__":
    clear_elections('elections.json')
    clear_directory('votes')
    clear_directory('results')