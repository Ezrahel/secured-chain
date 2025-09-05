import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');

// Test configuration
export const options = {
  stages: [
    { duration: '2m', target: 10 }, // Ramp up
    { duration: '5m', target: 50 }, // Stay at 50 users
    { duration: '2m', target: 100 }, // Ramp up to 100 users
    { duration: '5m', target: 100 }, // Stay at 100 users
    { duration: '2m', target: 0 }, // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests under 500ms
    http_req_failed: ['rate<0.1'], // Error rate under 10%
    errors: ['rate<0.1'],
  },
};

const BASE_URL = 'http://localhost:8080/api/v1';

// Test data
const testUsers = [
  { username: 'testuser1', email: 'test1@example.com', password: 'TestPassword123!' },
  { username: 'testuser2', email: 'test2@example.com', password: 'TestPassword123!' },
  { username: 'testuser3', email: 'test3@example.com', password: 'TestPassword123!' },
];

export default function () {
  const user = testUsers[Math.floor(Math.random() * testUsers.length)];
  
  // Test signup
  testSignup(user);
  sleep(1);
  
  // Test login
  const tokens = testLogin(user);
  sleep(1);
  
  if (tokens.accessToken) {
    // Test protected endpoints
    testGetSessions(tokens.accessToken);
    sleep(1);
    
    // Test token refresh
    testTokenRefresh(tokens.refreshToken);
    sleep(1);
    
    // Test logout
    testLogout(tokens.accessToken);
  }
  
  sleep(2);
}

function testSignup(user) {
  const payload = {
    fullname: `${user.username} Full`,
    username: user.username,
    email: user.email,
    password: user.password,
    confirm_password: user.password,
    device_id: `load-test-${__VU}-${__ITER}`,
  };
  
  const response = http.post(`${BASE_URL}/signup`, JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json' },
  });
  
  const success = check(response, {
    'signup status is 201 or 400': (r) => r.status === 201 || r.status === 400,
    'signup response time < 2s': (r) => r.timings.duration < 2000,
  });
  
  if (!success) {
    errorRate.add(1);
  }
}

function testLogin(user) {
  const payload = {
    username_or_email: user.username,
    password: user.password,
    device_id: `load-test-${__VU}-${__ITER}`,
  };
  
  const response = http.post(`${BASE_URL}/login`, JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json' },
  });
  
  const success = check(response, {
    'login status is 200 or 401': (r) => r.status === 200 || r.status === 401,
    'login response time < 1s': (r) => r.timings.duration < 1000,
  });
  
  if (!success) {
    errorRate.add(1);
    return {};
  }
  
  if (response.status === 200) {
    const body = JSON.parse(response.body);
    return {
      accessToken: body.access_token,
      refreshToken: body.refresh_token,
    };
  }
  
  return {};
}

function testGetSessions(accessToken) {
  const response = http.get(`${BASE_URL}/sessions`, {
    headers: { 
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
  });
  
  const success = check(response, {
    'sessions status is 200': (r) => r.status === 200,
    'sessions response time < 500ms': (r) => r.timings.duration < 500,
  });
  
  if (!success) {
    errorRate.add(1);
  }
}

function testTokenRefresh(refreshToken) {
  const payload = {
    refresh_token: refreshToken,
  };
  
  const response = http.post(`${BASE_URL}/token/refresh`, JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json' },
  });
  
  const success = check(response, {
    'refresh status is 200 or 401': (r) => r.status === 200 || r.status === 401,
    'refresh response time < 500ms': (r) => r.timings.duration < 500,
  });
  
  if (!success) {
    errorRate.add(1);
  }
}

function testLogout(accessToken) {
  const response = http.post(`${BASE_URL}/logout`, '{}', {
    headers: { 
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
  });
  
  const success = check(response, {
    'logout status is 200': (r) => r.status === 200,
    'logout response time < 500ms': (r) => r.timings.duration < 500,
  });
  
  if (!success) {
    errorRate.add(1);
  }
}

// Scenario for testing rate limiting
export function rateLimitTest() {
  const payload = {
    username_or_email: 'nonexistent@example.com',
    password: 'wrongpassword',
  };
  
  // Make rapid requests to trigger rate limiting
  for (let i = 0; i < 20; i++) {
    const response = http.post(`${BASE_URL}/login`, JSON.stringify(payload), {
      headers: { 'Content-Type': 'application/json' },
    });
    
    if (response.status === 429) {
      console.log('Rate limit triggered successfully');
      break;
    }
  }
}