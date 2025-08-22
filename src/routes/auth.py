from flask import Blueprint, request, jsonify
from datetime import datetime
import hashlib
import secrets

auth_bp = Blueprint('auth', __name__)

# In-memory storage for API keys (in production, this would be in a database)
VALID_API_KEYS = {
    'ca_demo_key_12345': {
        'user_id': 1,
        'created_at': datetime.utcnow(),
        'last_used': None,
        'is_active': True
    },
    'ca_test_key_67890': {
        'user_id': 1,
        'created_at': datetime.utcnow(),
        'last_used': None,
        'is_active': True
    }
}

@auth_bp.route('/validate-key', methods=['POST'])
def validate_api_key():
    """Validate an API key"""
    data = request.get_json()
    
    if not data or 'api_key' not in data:
        return jsonify({
            'valid': False,
            'message': 'API key is required'
        }), 400
    
    api_key = data['api_key']
    
    # Check if API key exists and is active
    if api_key in VALID_API_KEYS and VALID_API_KEYS[api_key]['is_active']:
        # Update last used timestamp
        VALID_API_KEYS[api_key]['last_used'] = datetime.utcnow()
        
        return jsonify({
            'valid': True,
            'message': 'API key is valid',
            'user_id': VALID_API_KEYS[api_key]['user_id']
        }), 200
    else:
        return jsonify({
            'valid': False,
            'message': 'Invalid or inactive API key'
        }), 401

@auth_bp.route('/generate-key', methods=['POST'])
def generate_api_key():
    """Generate a new API key"""
    data = request.get_json()
    user_id = data.get('user_id', 1)  # Default to user 1 for demo
    
    # Generate a new API key
    api_key = 'ca_' + secrets.token_urlsafe(32)
    
    # Store the API key
    VALID_API_KEYS[api_key] = {
        'user_id': user_id,
        'created_at': datetime.utcnow(),
        'last_used': None,
        'is_active': True
    }
    
    return jsonify({
        'api_key': api_key,
        'message': 'API key generated successfully'
    }), 201

@auth_bp.route('/revoke-key', methods=['POST'])
def revoke_api_key():
    """Revoke an API key"""
    data = request.get_json()
    
    if not data or 'api_key' not in data:
        return jsonify({
            'success': False,
            'message': 'API key is required'
        }), 400
    
    api_key = data['api_key']
    
    if api_key in VALID_API_KEYS:
        VALID_API_KEYS[api_key]['is_active'] = False
        return jsonify({
            'success': True,
            'message': 'API key revoked successfully'
        }), 200
    else:
        return jsonify({
            'success': False,
            'message': 'API key not found'
        }), 404

@auth_bp.route('/list-keys', methods=['GET'])
def list_api_keys():
    """List all API keys for a user (for admin purposes)"""
    user_id = request.args.get('user_id', 1, type=int)
    
    user_keys = []
    for key, data in VALID_API_KEYS.items():
        if data['user_id'] == user_id:
            user_keys.append({
                'api_key': key[:10] + '...',  # Mask the key for security
                'created_at': data['created_at'].isoformat(),
                'last_used': data['last_used'].isoformat() if data['last_used'] else None,
                'is_active': data['is_active']
            })
    
    return jsonify({
        'keys': user_keys,
        'total': len(user_keys)
    }), 200
