import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Shield, User, Key, Settings, Activity, AlertCircle, CheckCircle, Lock, Database, Mail, Server } from 'lucide-react';

interface AuthResponse {
  access_token?: string;
  refresh_token?: string;
  user?: {
    id: string;
    username: string;
    email: string;
    fullname: string;
  };
  message?: string;
  error?: string;
}

interface Session {
  id: string;
  device_id: string;
  ip_address: string;
  user_agent: string;
  created_at: string;
}

export default function AuthTestInterface() {
  const [activeTab, setActiveTab] = useState('signup');
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [user, setUser] = useState<AuthResponse['user'] | null>(null);
  const [response, setResponse] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [sessions, setSessions] = useState<Session[]>([]);

  // Form states
  const [signupForm, setSignupForm] = useState({
    fullname: 'John Doe',
    username: 'johndoe',
    email: 'john@example.com',
    password: 'SecurePassword123!',
    confirm_password: 'SecurePassword123!',
    device_id: 'web-browser-001'
  });

  const [loginForm, setLoginForm] = useState({
    username_or_email: 'johndoe',
    password: 'SecurePassword123!',
    device_id: 'web-browser-001'
  });

  const [resetForm, setResetForm] = useState({
    email: 'john@example.com'
  });

  const [mfaCode, setMfaCode] = useState('123456');

  const API_BASE = 'http://localhost:8080/api/v1';

  const makeRequest = async (endpoint: string, method: string = 'GET', body?: Record<string, unknown>) => {
    setLoading(true);
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      if (accessToken) {
        headers.Authorization = `Bearer ${accessToken}`;
      }

      const response = await fetch(`${API_BASE}${endpoint}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        credentials: 'include'
      });

      const data = await response.json();
      
      setResponse(JSON.stringify(data, null, 2));
      
      if (response.ok) {
        if (data.access_token) {
          setAccessToken(data.access_token);
          setUser(data.user);
        }
        return data;
      } else {
        throw new Error(data.error || 'Request failed');
      }
    } catch (error) {
      setResponse(JSON.stringify({ error: error.message }, null, 2));
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = async () => {
    await makeRequest('/signup', 'POST', signupForm);
  };

  const handleLogin = async () => {
    const result = await makeRequest('/login', 'POST', loginForm);
    if (result.access_token) {
      setActiveTab('dashboard');
    }
  };

  const handleLogout = async () => {
    await makeRequest('/logout', 'POST');
    setAccessToken(null);
    setUser(null);
    setActiveTab('login');
  };

  const handleRefreshToken = async () => {
    await makeRequest('/token/refresh', 'POST');
  };

  const handlePasswordReset = async () => {
    await makeRequest('/password-reset/request', 'POST', resetForm);
  };

  const handleGetSessions = async () => {
    const result = await makeRequest('/sessions');
    setSessions(result.sessions || []);
  };

  const handleEnableMFA = async () => {
    await makeRequest('/mfa/enable', 'POST', { password: loginForm.password });
  };

  const handleVerifyMFA = async () => {
    await makeRequest('/mfa/verify', 'POST', { code: mfaCode });
  };

  const handleDisableMFA = async () => {
    await makeRequest('/mfa/disable', 'POST');
  };

  useEffect(() => {
    if (accessToken && activeTab === 'dashboard') {
      handleGetSessions();
    }
  }, [accessToken, activeTab]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="h-12 w-12 text-blue-600 mr-3" />
            <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
              Auth Service Test Interface
            </h1>
          </div>
          <p className="text-lg text-muted-foreground">
            Production-ready Go authentication service with FAANG-level security
          </p>
          {user && (
            <Badge variant="secondary" className="mt-2">
              Logged in as {user.username} ({user.email})
            </Badge>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Panel - API Testing */}
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Key className="h-5 w-5 mr-2" />
                  Authentication API
                </CardTitle>
                <CardDescription>
                  Test all authentication endpoints with real API calls
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs value={activeTab} onValueChange={setActiveTab}>
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="signup">Signup</TabsTrigger>
                    <TabsTrigger value="login">Login</TabsTrigger>
                    <TabsTrigger value="reset">Reset</TabsTrigger>
                    <TabsTrigger value="dashboard" disabled={!accessToken}>
                      Dashboard
                    </TabsTrigger>
                  </TabsList>

                  <TabsContent value="signup" className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="fullname">Full Name</Label>
                        <Input
                          id="fullname"
                          value={signupForm.fullname}
                          onChange={(e) => setSignupForm({...signupForm, fullname: e.target.value})}
                        />
                      </div>
                      <div>
                        <Label htmlFor="username">Username</Label>
                        <Input
                          id="username"
                          value={signupForm.username}
                          onChange={(e) => setSignupForm({...signupForm, username: e.target.value})}
                        />
                      </div>
                    </div>
                    <div>
                      <Label htmlFor="email">Email</Label>
                      <Input
                        id="email"
                        type="email"
                        value={signupForm.email}
                        onChange={(e) => setSignupForm({...signupForm, email: e.target.value})}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="password">Password</Label>
                        <Input
                          id="password"
                          type="password"
                          value={signupForm.password}
                          onChange={(e) => setSignupForm({...signupForm, password: e.target.value})}
                        />
                      </div>
                      <div>
                        <Label htmlFor="confirm_password">Confirm Password</Label>
                        <Input
                          id="confirm_password"
                          type="password"
                          value={signupForm.confirm_password}
                          onChange={(e) => setSignupForm({...signupForm, confirm_password: e.target.value})}
                        />
                      </div>
                    </div>
                    <Button onClick={handleSignup} disabled={loading} className="w-full">
                      {loading ? 'Creating Account...' : 'Create Account'}
                    </Button>
                  </TabsContent>

                  <TabsContent value="login" className="space-y-4">
                    <div>
                      <Label htmlFor="username_or_email">Username or Email</Label>
                      <Input
                        id="username_or_email"
                        value={loginForm.username_or_email}
                        onChange={(e) => setLoginForm({...loginForm, username_or_email: e.target.value})}
                      />
                    </div>
                    <div>
                      <Label htmlFor="login_password">Password</Label>
                      <Input
                        id="login_password"
                        type="password"
                        value={loginForm.password}
                        onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
                      />
                    </div>
                    <Button onClick={handleLogin} disabled={loading} className="w-full">
                      {loading ? 'Signing In...' : 'Sign In'}
                    </Button>
                    {accessToken && (
                      <div className="flex gap-2">
                        <Button onClick={handleRefreshToken} variant="outline" size="sm">
                          Refresh Token
                        </Button>
                        <Button onClick={handleLogout} variant="destructive" size="sm">
                          Logout
                        </Button>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="reset" className="space-y-4">
                    <div>
                      <Label htmlFor="reset_email">Email Address</Label>
                      <Input
                        id="reset_email"
                        type="email"
                        value={resetForm.email}
                        onChange={(e) => setResetForm({...resetForm, email: e.target.value})}
                      />
                    </div>
                    <Button onClick={handlePasswordReset} disabled={loading} className="w-full">
                      {loading ? 'Sending Reset Email...' : 'Send Reset Email'}
                    </Button>
                  </TabsContent>

                  <TabsContent value="dashboard" className="space-y-4">
                    {user && (
                      <div className="space-y-4">
                        <Alert>
                          <CheckCircle className="h-4 w-4" />
                          <AlertDescription>
                            Successfully authenticated as <strong>{user.fullname}</strong>
                          </AlertDescription>
                        </Alert>

                        <div className="grid grid-cols-2 gap-4">
                          <Card>
                            <CardHeader className="pb-3">
                              <CardTitle className="text-sm">User Info</CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-2">
                              <div className="text-sm">
                                <span className="font-medium">ID:</span> {user.id}
                              </div>
                              <div className="text-sm">
                                <span className="font-medium">Username:</span> {user.username}
                              </div>
                              <div className="text-sm">
                                <span className="font-medium">Email:</span> {user.email}
                              </div>
                            </CardContent>
                          </Card>

                          <Card>
                            <CardHeader className="pb-3">
                              <CardTitle className="text-sm">MFA Controls</CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-2">
                              <div className="flex gap-2">
                                <Input
                                  placeholder="MFA Code"
                                  value={mfaCode}
                                  onChange={(e) => setMfaCode(e.target.value)}
                                  className="text-sm"
                                />
                              </div>
                              <div className="flex gap-1">
                                <Button onClick={handleEnableMFA} size="sm" variant="outline">
                                  Enable
                                </Button>
                                <Button onClick={handleVerifyMFA} size="sm" variant="outline">
                                  Verify
                                </Button>
                                <Button onClick={handleDisableMFA} size="sm" variant="outline">
                                  Disable
                                </Button>
                              </div>
                            </CardContent>
                          </Card>
                        </div>

                        <Card>
                          <CardHeader>
                            <CardTitle className="text-sm flex items-center">
                              <Activity className="h-4 w-4 mr-2" />
                              Active Sessions
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <Button onClick={handleGetSessions} size="sm" className="mb-3">
                              Refresh Sessions
                            </Button>
                            <div className="space-y-2">
                              {sessions.map((session) => (
                                <div key={session.id} className="p-3 border rounded-lg text-sm">
                                  <div className="flex justify-between items-start">
                                    <div>
                                      <div className="font-medium">Device: {session.device_id}</div>
                                      <div className="text-muted-foreground">IP: {session.ip_address}</div>
                                      <div className="text-muted-foreground text-xs">
                                        Created: {new Date(session.created_at).toLocaleString()}
                                      </div>
                                    </div>
                                    <Badge variant="secondary">Active</Badge>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </CardContent>
                        </Card>
                      </div>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>

          {/* Right Panel - Response & Documentation */}
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Settings className="h-5 w-5 mr-2" />
                  API Response
                </CardTitle>
                <CardDescription>
                  Real-time API responses and status
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-96 w-full border rounded-lg p-4">
                  <pre className="text-sm font-mono whitespace-pre-wrap">
                    {response || 'No response yet. Make an API call to see the response here.'}
                  </pre>
                </ScrollArea>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Security Features</CardTitle>
                <CardDescription>
                  FAANG-level security controls implemented
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="flex items-center space-x-2">
                    <Lock className="h-4 w-4 text-green-600" />
                    <span className="text-sm">JWT + Refresh Tokens</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Shield className="h-4 w-4 text-green-600" />
                    <span className="text-sm">Argon2id Hashing</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Database className="h-4 w-4 text-green-600" />
                    <span className="text-sm">Device Binding</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Mail className="h-4 w-4 text-green-600" />
                    <span className="text-sm">Email Verification</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Key className="h-4 w-4 text-green-600" />
                    <span className="text-sm">MFA Support</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Activity className="h-4 w-4 text-green-600" />
                    <span className="text-sm">Audit Logging</span>
                  </div>
                </div>

                <Separator />

                <div className="space-y-2">
                  <h4 className="font-medium text-sm">Quick Setup</h4>
                  <div className="text-xs space-y-1 text-muted-foreground">
                    <div>1. Start PostgreSQL: <code>make dev-up</code></div>
                    <div>2. Run migrations: <code>make migrate</code></div>
                    <div>3. Start API server: <code>make run</code></div>
                    <div>4. Test endpoints using this interface</div>
                  </div>
                </div>

                <Separator />

                <div className="space-y-2">
                  <h4 className="font-medium text-sm">API Endpoints</h4>
                  <div className="text-xs space-y-1 text-muted-foreground">
                    <div><code>POST /api/v1/signup</code> - User registration</div>
                    <div><code>POST /api/v1/login</code> - Authentication</div>
                    <div><code>GET /api/v1/confirm-email</code> - Email confirmation</div>
                    <div><code>POST /api/v1/token/refresh</code> - Token rotation</div>
                    <div><code>POST /api/v1/logout</code> - Session termination</div>
                    <div><code>GET /api/v1/sessions</code> - Active sessions</div>
                    <div><code>POST /api/v1/mfa/*</code> - MFA operations</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}