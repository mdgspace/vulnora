import { useState, ReactElement } from 'react';
import { Link, useNavigate } from "react-router-dom";
import { Shield, Home, History, Info, UserCircle, LogOut, X, LayoutDashboard } from 'lucide-react';

interface UserData {
  firstName?: string;
  email?: string;
  scansDone?: number;
}

const Navbar = (): ReactElement => {
  const navigate = useNavigate();

  const Logout = (): void => {
    localStorage.clear();
    setTimeout(() => {
      navigate("/login");
    }, 1500);
  };

  const [showProfileCard, setShowProfileCard] = useState<boolean>(false);
  const [userData] = useState<UserData>({});

  return (
    <nav className="fixed top-0 inset-x-0 z-20 bg-black/40 backdrop-blur-md rounded-b-xl px-6 py-4 shadow-xl">
      <div className="container mx-auto flex items-center justify-between">
        <a href="#" className="flex items-center text-white text-xl font-bold tracking-wider">
          <Shield className="w-8 h-8 mr-2 text-green-400" />
          VULN<span className="text-green-400">ORA</span>
        </a>

        <div className="flex items-center space-x-6">
          <Link to="/" className="flex items-center text-gray-400 hover:text-green-400 transition-colors">
            <Home className="w-5 h-5 mr-1" /> Home
          </Link>
          <Link to="/home" className="flex items-center text-gray-400 hover:text-green-400 transition-colors">
            <LayoutDashboard className="w-5 h-5 mr-1" /> Dashboard
          </Link>
          <Link to="/history" className="flex items-center text-gray-400 hover:text-green-400 transition-colors">
            <History className="w-5 h-5 mr-1" /> History
          </Link>
          <Link to="/#about" className="flex items-center text-gray-400 hover:text-green-400 transition-colors">
            <Info className="w-5 h-5 mr-1" /> About
          </Link>
        </div>

        <div className="relative">
          <div
            className="text-gray-400 hover:text-white transition-colors cursor-pointer"
            onClick={() => setShowProfileCard(!showProfileCard)}
          >
            <UserCircle className="w-8 h-8" />
          </div>

          {showProfileCard && (
            <div className="absolute top-14 right-0 mt-2 w-64 bg-black/70 backdrop-blur-md rounded-xl shadow-2xl p-4 border border-green-400/20 text-white z-30 animate-fade-in-down">
              <button
                onClick={() => setShowProfileCard(false)}
                className="absolute top-2 right-2 p-1 rounded-full text-gray-400 hover:bg-gray-700 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>

              <div className="flex items-center mb-4">
                <UserCircle className="w-10 h-10 text-green-400 mr-3" />
                <div>
                  <h4 className="font-bold text-lg">{userData.firstName}</h4>
                  <p className="text-xs text-gray-400">{userData.email}</p>
                </div>
              </div>
              <div className="text-sm border-t border-gray-700 pt-3 mb-3">
                <p className="text-gray-300">Scans Completed: <span className="text-green-400 font-semibold">
                  XX
                  </span></p>
              </div>
              <button
                onClick={() => {
                  Logout();
                  setShowProfileCard(false);
                }}
                className="w-full flex items-center justify-center py-2 px-4 rounded-lg bg-red-600/50 hover:bg-red-600/70 transition-all text-white font-bold text-sm"
              >
                <LogOut className="w-4 h-4 mr-2" /> Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
