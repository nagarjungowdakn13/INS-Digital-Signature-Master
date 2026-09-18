"""
Digital Signature Tool - Flask Backend API

This module provides REST API endpoints for the digital signature tool.
"""

import os
import json
import base64
import tempfile
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename

from sha256 import SHA256
from rsa import RSA
from file_handler import FileHandler
from key_manager import KeyManager
from signature_manager import SignatureManager

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# Initialize components
sha256 = SHA256()
key_manager = KeyManager(keys_dir="keys")
signature_manager = SignatureManager()

# Store RSA instance globally (for demo purposes)
rsa_instance = None


def get_rsa_instance():
    """Get or create RSA instance with loaded keys."""
    global rsa_instance
    if rsa_instance is None:
        if key_manager.keys_exist():
            rsa_instance = RSA(key_length=1024)
            public_key, private_key = key_manager.load_keys()
            rsa_instance.set_keys(public_key, private_key)
    return rsa_instance


@app.route('/')
def index():
    """Serve the main page."""
    return render_template('index.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current system status including key availability."""
    keys_exist = key_manager.keys_exist()
    key_info = None
    
    if keys_exist:
        key_info = key_manager.get_key_info()
    
    return jsonify({
        'success': True,
        'keys_exist': keys_exist,
        'key_info': key_info
    })


@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    """Generate new RSA key pair."""
    global rsa_instance
    
    try:
        data = request.get_json() or {}
        key_size = data.get('key_size', 1024)
        
        # Validate key size
        if key_size not in [1024, 2048, 4096]:
            return jsonify({
                'success': False,
                'error': 'Invalid key size. Choose 1024, 2048, or 4096.'
            }), 400
        
        # Generate new keys
        rsa_instance = RSA(key_length=key_size)
        
        # Save keys
        private_path, public_path = key_manager.save_keys(
            rsa_instance.get_public_key(),
            rsa_instance.get_private_key(),
            key_size=key_size
        )
        
        return jsonify({
            'success': True,
            'message': f'{key_size}-bit RSA key pair generated successfully!',
            'key_size': key_size,
            'private_key_path': private_path,
            'public_key_path': public_path
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/sign-text', methods=['POST'])
def sign_text():
    """Sign a text message."""
    global rsa_instance
    
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({
                'success': False,
                'error': 'No message provided'
            }), 400
        
        message = data['message']
        
        # Generate fresh keys for text signing (original behavior)
        temp_rsa = RSA(key_length=1024)
        
        # Calculate hash
        message_bytes = message.encode('utf-8')
        message_hash = sha256.hash(message_bytes)
        hash_hex = message_hash.hex().upper()
        
        # Sign the hash
        signature = temp_rsa.encrypt(hash_hex.encode('utf-8'), temp_rsa.get_private_key())
        signature_hex = signature.hex().upper()
        
        # Verify (simulate Alice)
        decrypted = temp_rsa.decrypt(signature, temp_rsa.get_public_key())
        decrypted_str = decrypted.decode('utf-8')
        
        is_valid = decrypted_str == hash_hex
        
        return jsonify({
            'success': True,
            'signing': {
                'message': message,
                'hash': hash_hex,
                'signature': signature_hex[:100] + '...' if len(signature_hex) > 100 else signature_hex
            },
            'verification': {
                'calculated_hash': hash_hex,
                'decrypted_hash': decrypted_str,
                'is_valid': is_valid,
                'message': 'Signature verified! The message is authentic.' if is_valid else 'Signature invalid!'
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/sign-file', methods=['POST'])
def sign_file():
    """Sign an uploaded file."""
    try:
        rsa = get_rsa_instance()
        if rsa is None:
            return jsonify({
                'success': False,
                'error': 'No RSA keys found. Please generate keys first.'
            }), 400
        
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        # Read file content
        file_content = file.read()
        filename = secure_filename(file.filename)
        
        # Calculate hash
        file_hash = sha256.hash(file_content)
        hash_hex = file_hash.hex().upper()
        
        # Sign the hash
        signature = rsa.sign(file_hash)
        
        # Get key info
        key_info = key_manager.get_key_info()
        key_size = key_info.get('key_size', 1024) if key_info else 1024
        
        # Create signature data
        signature_data = {
            "format_version": "1.0",
            "algorithm": "RSA-SHA256",
            "key_size": key_size,
            "timestamp": datetime.now().isoformat(),
            "original_filename": filename,
            "file_hash": hash_hex,
            "signature": base64.b64encode(signature).decode('utf-8')
        }
        
        return jsonify({
            'success': True,
            'message': 'File signed successfully!',
            'filename': filename,
            'hash': hash_hex,
            'signature_data': signature_data,
            'signature_json': json.dumps(signature_data, indent=2)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/verify-file', methods=['POST'])
def verify_file():
    """Verify a file with its signature."""
    try:
        rsa = get_rsa_instance()
        if rsa is None:
            return jsonify({
                'success': False,
                'error': 'No RSA keys found. Please generate keys first.'
            }), 400
        
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400
        
        if 'signature' not in request.form and 'signature_file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No signature provided'
            }), 400
        
        file = request.files['file']
        file_content = file.read()
        filename = secure_filename(file.filename)
        
        # Get signature data
        if 'signature_file' in request.files and request.files['signature_file'].filename:
            sig_file = request.files['signature_file']
            signature_json = sig_file.read().decode('utf-8')
        else:
            signature_json = request.form.get('signature')
        
        try:
            signature_data = json.loads(signature_json)
        except json.JSONDecodeError:
            return jsonify({
                'success': False,
                'error': 'Invalid signature format'
            }), 400
        
        # Calculate hash of the file
        file_hash = sha256.hash(file_content)
        calculated_hash = file_hash.hex().upper()
        
        # Get signature bytes
        signature_bytes = base64.b64decode(signature_data['signature'].encode('utf-8'))
        
        # Verify signature
        is_valid = rsa.verify_signature(signature_bytes, file_hash)
        
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'filename': filename,
            'calculated_hash': calculated_hash,
            'original_hash': signature_data.get('file_hash', 'N/A'),
            'algorithm': signature_data.get('algorithm', 'RSA-SHA256'),
            'key_size': signature_data.get('key_size', 'Unknown'),
            'signed_on': signature_data.get('timestamp', 'Unknown'),
            'original_filename': signature_data.get('original_filename', 'Unknown'),
            'message': 'Signature is VALID! The file is authentic.' if is_valid else 'Signature is INVALID! The file may have been tampered with.'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/download-signature', methods=['POST'])
def download_signature():
    """Download signature as a .sig file."""
    try:
        data = request.get_json()
        if not data or 'signature_data' not in data:
            return jsonify({
                'success': False,
                'error': 'No signature data provided'
            }), 400
        
        signature_data = data['signature_data']
        filename = secure_filename(data.get('filename', 'signature')) or 'signature'
        filename += '.sig'

        # Create temp file
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(temp_path, 'w') as f:
            json.dump(signature_data, f, indent=2)
        
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json'
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    # Ensure templates and static directories exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    print("\n" + "=" * 50)
    print("   Digital Signature Tool - Web Interface")
    print("=" * 50)
    print("\nStarting server at http://127.0.0.1:5000")
    print("Press Ctrl+C to stop the server\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)
