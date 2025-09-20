import React, { useEffect, useState } from 'react';
import { Loader, UserPlus } from 'lucide-react';
import { handleSuccess } from '../components/utils';
import { ToastContainer } from 'react-toastify';
import { jwtDecode } from "jwt-decode";
import { Link, useNavigate } from 'react-router-dom';
import api from '../components/api';

// The main App component which renders the entire signup page.
const Login = () => {
  // Checks if user is already logged in.
  const navigate = useNavigate();
  useEffect(() => {
      try{
        const token = localStorage.getItem("ACCESS_TOKEN");
        const decoded = jwtDecode(token);
        const tokenExpiration = decoded.exp;
        const now = Date.now() / 1000;
        
        if (token && tokenExpiration > now) {
            navigate("/home");
        }
      } catch(err){
        console.error(err);
      }
    }
  )

  // State to manage the form data.
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });

  // State for UI feedback, like loading and messages.
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  // Handles changes to all form inputs using the 'name' attribute.
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  // Handles form submission.
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    const isValidPassword = (password) => {
    const minLength = 6;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*:]/.test(password);

    return (
      password.length > minLength &&
      hasUpperCase &&
      hasLowerCase &&
      hasNumber &&
      hasSpecialChar
    );
  };

    // Basic client-side validation.
    if (!formData.email || !formData.password) {
      setMessage('All fields are required.');
      setLoading(false);
      return;
    }
    
    if (!isValidPassword(formData.password)) {
      setMessage('Password must be longer than 6 characters and include number, specal character(!, @, #, $, %, ^, &, *, :), uppercase and lowercase letters.');
      setLoading(false);
      return;
    }

    try {
      const res = await api.post("/api/auth/login", formData);
      // console.log(res);
      if (res.status === 200) {
        // console.log(res);
        localStorage.setItem("ACCESS_TOKEN", res.data.token);
        handleSuccess("Login Successful!");
        setTimeout(() => {
          navigate("/home");
        }, 1500);
      } else {
        localStorage.clear();
        handleError("Login Failed!");
        setLoading(false);
        setMessage("Invalid email or password.");
        setTimeout(() => {
          navigate("/login");
        }, 1500);
      }
    } catch (err) {
      localStorage.clear();
      handleError(err);
      setTimeout(() => {
        navigate("/login");
      }, 1500);
    }

    // Simulate a successful network request with a delay.
    setTimeout(() => {
      setLoading(false);
      setMessage('Logged in successfully! Redirecting to your Dashboard...');
      // console.log(formData);
    }, 0);
  };

  return (
    <div className="min-h-screen bg-gray-950 text-green-400 font-mono relative overflow-x-hidden p-4 sm:p-8 flex items-center justify-center">
      {/* Background Grid Pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,65,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,65,0.03)_1px,transparent_1px)] bg-[size:50px_50px]"></div>

      {/* Main Signup Form Container */}
      <div className="relative z-10 w-full max-w-lg bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-xl p-8 shadow-2xl transform transition-all duration-300 hover:shadow-green-500/20">

        {/* Header Section */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <UserPlus className="w-10 h-10 text-green-400 mr-2" />
            <h1 className="text-3xl font-bold text-white tracking-wider">
              Login
            </h1>
          </div>
          <p className="text-gray-400">
            Login to your account.
          </p>
          <div className="w-16 h-1 bg-gradient-to-r from-transparent via-green-400 to-transparent mx-auto mt-4"></div>
        </div>

        {/* The Form */}
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Email Input */}
          <div className="relative">
            <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-1">
              Email Address
            </label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              required
              className="w-full bg-gray-800/50 border border-green-400/30 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:border-green-400 focus:ring-2 focus:ring-green-400/20 focus:outline-none transition-all"
              placeholder="Enter your email"
            />
          </div>

          {/* Password Input */}
          <div className="relative">
            <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-1">
              Password
            </label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleInputChange}
              required
              className="w-full bg-gray-800/50 border border-green-400/30 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:border-green-400 focus:ring-2 focus:ring-green-400/20 focus:outline-none transition-all"
              placeholder="Create a password"
            />
          </div>

          {/* Login Button with Loading State */}
          <div>
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-green-400 to-emerald-500 text-black font-semibold text-lg hover:from-green-500 hover:to-emerald-600 disabled:from-gray-600 disabled:to-gray-700 disabled:text-gray-400 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-all transform hover:scale-105 disabled:scale-100 shadow-md hover:shadow-lg"
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <Loader className="w-5 h-5 mr-2 animate-spin" />
                  Logging in...
                </span>
              ) : (
                <span>Login</span>
              )}
            </button>
          </div>
        </form>

        {/* Message box for success or error */}
        {message && (
          <div className={`mt-6 text-center text-sm font-bold ${message.includes('successfully') ? 'text-green-400' : 'text-red-400'}`}>
            {message}
          </div>
        )}

        <div className="mt-8 text-center text-gray-400">
          <p>
            Don't have an account?{" "}
            <Link to="/signup" className="font-medium text-[#6ab04c] hover:text-green-400 transition duration-200">
              Sign Up
            </Link>
          </p>
        </div>
      </div>
    <ToastContainer />
    </div>
  );
};

export default Login;
