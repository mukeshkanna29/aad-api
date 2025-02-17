import pytest
from flask import json
from edu_api import app, db, User, Assignment, blacklist

@pytest.fixture
def client():
    """Setup and teardown the test client"""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Use in-memory DB for testing
    with app.app_context():
        db.create_all()
    client = app.test_client()
    yield client
    with app.app_context():
        db.session.remove()
        db.drop_all()

def test_register(client):
    """Test user registration"""
    response = client.post('/register', json={
        'username': 'testuser1',
        'password': 'password1234',
        'role': 'student'
    })
    assert response.status_code == 201
    assert response.json['message'] == 'User registered successfully'

def test_login(client):
    """Test user login and token generation"""
    client.post('/register', json={'username': 'testuser', 'password': 'password123', 'role': 'student'})
    response = client.post('/login', json={'username': 'testuser', 'password': 'password123'})
    assert response.status_code == 200
    assert 'access_token' in response.json
    return response.json['access_token']

def test_protected_route(client):
    """Test access to protected route with valid token"""
    token = test_login(client)
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json['message'] == 'Access granted'

def test_upload_assignment(client):
    """Test assignment upload for students"""
    token = test_login(client)
    response = client.post('/assignments/upload', headers={'Authorization': f'Bearer {token}'}, json={
        'title': 'Assignment 1',
        'content': 'This is a test assignment'
    })
    assert response.status_code == 201
    assert response.json['message'] == 'Assignment uploaded successfully'

def test_get_assignments(client):
    """Test fetching all assignments"""
    token = test_login(client)
    client.post('/assignments/upload', headers={'Authorization': f'Bearer {token}'}, json={
        'title': 'Assignment 1',
        'content': 'This is a test assignment'
    })
    response = client.get('/assignments', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert len(response.json) > 0

def test_give_feedback(client):
    """Test faculty giving feedback on an assignment"""
    client.post('/register', json={'username': 'facultyuser', 'password': 'password123', 'role': 'faculty'})
    student_token = test_login(client)
    faculty_token = client.post('/login', json={'username': 'facultyuser', 'password': 'password123'}).json['access_token']
    
    client.post('/assignments/upload', headers={'Authorization': f'Bearer {student_token}'}, json={
        'title': 'Assignment 1',
        'content': 'This is a test assignment'
    })
    
    response = client.post('/assignments/feedback/1', headers={'Authorization': f'Bearer {faculty_token}'}, json={
        'feedback': 'Good work!'
    })
    assert response.status_code == 200
    assert response.json['message'] == 'Feedback added successfully'

def test_logout(client):
    """Test user logout and token blacklist"""
    token = test_login(client)
    response = client.post('/logout', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json['message'] == 'Successfully logged out'
    
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 401  # Token should be invalid

if __name__ == "__main__":
    pytest.main()
