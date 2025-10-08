import { Link } from 'react-router-dom';
import { Shield, BugPlay, Rocket, Lock, ShieldAlert } from 'lucide-react';

// Main App component containing the entire landing page
export default function App() {
  return (
    <div className="bg-gray-950 text-gray-200 font-sans min-h-screen">
      
      {/* Header with navigation */}
      <header className="fixed top-0 left-0 w-full z-10 bg-gray-950/70 backdrop-blur-sm p-4 md:px-12 flex justify-between items-center border-b border-green-500/20">
        <div className="flex items-center space-x-2">
        <a href="#" className="flex items-center text-white text-xl font-bold tracking-wider">
          <Shield className="w-8 h-8 mr-2 text-green-400" />
          VULN<span className="text-green-400">ORA</span>
        </a>
        </div>
        <nav className="hidden md:flex space-x-8">
          <a href="#about" className="text-gray-400 hover:text-green-500 transition-colors duration-300">About</a>
          <a href="#features" className="text-gray-400 hover:text-green-500 transition-colors duration-300">Features</a>
          <a href="#why-us" className="text-gray-400 hover:text-green-500 transition-colors duration-300">Why Vulnora</a>
          <Link to="/signup" className="text-gray-400 hover:text-green-500 transition-colors duration-300">Sign Up</Link>
        </nav>
      </header>
      
      {/* Main Hero Section */}
      <main className="pt-24 pb-16 px-4 md:px-12">
        <section className="text-center py-20 px-4">
          <h2 className="text-4xl md:text-6xl font-extrabold text-white leading-tight mb-4 tracking-tight">
            Proactive Security <br /> for a Digital World
          </h2>
          <p className="text-lg md:text-xl text-gray-400 max-w-3xl mx-auto mb-8">
            Simulate realistic attacks and identify vulnerabilities before they are exploited. Vulnora provides a safe, controlled environment to test your web application's resilience.
          </p>
          <Link to="/signup" className="inline-block bg-green-500 hover:bg-green-600 text-gray-950 font-bold py-3 px-8 rounded-full shadow-lg transition-transform transform hover:scale-105 duration-300">
            Get Started
          </Link>
        </section>

        {/* About Section */}
        <section id="about" className="py-20">
          <div className="max-w-6xl mx-auto grid md:grid-cols-2 gap-16 items-center">
            <div>
              <h3 className="text-3xl font-bold text-green-400 mb-4">About Vulnora</h3>
              <p className="text-gray-400 leading-relaxed">
                In a constantly evolving threat landscape, staying ahead of attackers is crucial. Vulnora is a powerful web security scanner designed for developers and security professionals. It's built to be intuitive, giving you the ability to simulate common attack vectors like SQL Injection, JWT Attack, and more, all within a safe, controlled environment. Our goal is to empower you to build more secure applications by providing clear, actionable insights.
              </p>
            </div>
            <div className="relative">
              <div className="absolute inset-0 bg-green-500/10 rounded-3xl blur-3xl"></div>
              <div className="relative p-6 bg-gray-800 rounded-2xl shadow-xl border border-green-500/20 z-1">
                <p className="font-mono text-sm text-green-400 mb-4">~$ cd /vulnora</p>
                <p className="font-mono text-sm text-gray-400">
                  <span className="text-red-400">[WARNING]</span> Potential threats detected...
                </p>
                <p className="font-mono text-sm text-white">
                  - SQL Injection <span className="text-yellow-400">[STATUS: VULNERABLE]</span>
                </p>
                <p className="font-mono text-sm text-green-400 mt-4">~$ initiate-scan --target="example.com"</p>
              </div>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section id="features" className="py-20">
          <h3 className="text-3xl font-bold text-center text-green-400 mb-12">Key Features</h3>
          <div className="max-w-6xl mx-auto grid sm:grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="bg-gray-800 p-8 rounded-2xl shadow-lg border border-green-500/20 transition-all duration-300 hover:border-green-400 hover:shadow-green-500/20">
              <BugPlay className="w-12 h-12 text-green-500 mb-4" />
              <h4 className="text-xl font-semibold mb-2">Comprehensive Scanning</h4>
              <p className="text-gray-400">Detect a wide range of common web vulnerabilities, including IP Scratching, JWT, SQLi.</p>
            </div>
            <div className="bg-gray-800 p-8 rounded-2xl shadow-lg border border-green-500/20 transition-all duration-300 hover:border-green-400 hover:shadow-green-500/20">
              <Rocket className="w-12 h-12 text-green-500 mb-4" />
              <h4 className="text-xl font-semibold mb-2">Fast & Accurate Results</h4>
              <p className="text-gray-400">Get quick and precise reports on your application's security posture with detailed findings.</p>
            </div>
            <div className="bg-gray-800 p-8 rounded-2xl shadow-lg border border-green-500/20 transition-all duration-300 hover:border-green-400 hover:shadow-green-500/20">
              <ShieldAlert className="w-12 h-12 text-green-500 mb-4" />
              <h4 className="text-xl font-semibold mb-2">Actionable Insights</h4>
              <p className="text-gray-400">Receive clear explanations and recommendations for fixing identified vulnerabilities.</p>
            </div>
            <div className="bg-gray-800 p-8 rounded-2xl shadow-lg border border-green-500/20 transition-all duration-300 hover:border-green-400 hover:shadow-green-500/20">
              <Lock className="w-12 h-12 text-green-500 mb-4" />
              <h4 className="text-xl font-semibold mb-2">Secure Simulations</h4>
              <p className="text-gray-400">Safely simulate attacks without risk to your production environment or data.</p>
            </div>
          </div>
        </section>

        {/* Why Use Vulnora Section */}
        <section id="why-us" className="py-20">
          <div className="max-w-6xl mx-auto text-center">
            <h3 className="text-3xl font-bold text-green-400 mb-4">Why Trust Vulnora?</h3>
            <p className="text-gray-400 max-w-3xl mx-auto mb-12">
              Choosing the right tool for security is a critical decision. Here's why Vulnora stands out.
            </p>
            <div className="grid md:grid-cols-3 gap-8 text-left">
              <div className="bg-gray-800 p-8 rounded-2xl border border-green-500/20 transition-transform transform hover:scale-105 duration-300">
                <div className="w-12 h-12 bg-green-500 rounded-full flex items-center justify-center text-gray-950 font-bold text-2xl mb-4">1</div>
                <h4 className="text-xl font-semibold mb-2">Built for Developers</h4>
                <p className="text-gray-400">Our platform is designed to seamlessly integrate into your development workflow, providing instant feedback without complexity.</p>
              </div>
              <div className="bg-gray-800 p-8 rounded-2xl border border-green-500/20 transition-transform transform hover:scale-105 duration-300">
                <div className="w-12 h-12 bg-green-500 rounded-full flex items-center justify-center text-gray-950 font-bold text-2xl mb-4">2</div>
                <h4 className="text-xl font-semibold mb-2">Cost-Effective Security</h4>
                <p className="text-gray-400">Get enterprise-level security scanning without the prohibitive cost. Protect your projects on any budget.</p>
              </div>
              <div className="bg-gray-800 p-8 rounded-2xl border border-green-500/20 transition-transform transform hover:scale-105 duration-300">
                <div className="w-12 h-12 bg-green-500 rounded-full flex items-center justify-center text-gray-950 font-bold text-2xl mb-4">3</div>
                <h4 className="text-xl font-semibold mb-2">Community-Driven</h4>
                <p className="text-gray-400">Join a growing community of security enthusiasts and developers who are passionate about building a safer web.</p>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="py-8 text-center text-gray-500 border-t border-green-500/20">
        <p>&copy; 2024 Vulnora. All rights reserved.</p>
      </footer>
    </div>
  );
}
