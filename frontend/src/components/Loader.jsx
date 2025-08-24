import React, { useState, useEffect } from 'react';
import { Loader, Code, Shield } from 'lucide-react';

// The main App component for the loading page.
const Load = () => {
  // State variables to manage the loading status and the dynamic activity log.
  const [statusMessage, setStatusMessage] = useState('Initializing system...');
  const [activityLog, setActivityLog] = useState(['']);

  // An array of messages to simulate different, non-finite loading stages.
  const loadingMessages = [
    'Establishing secure connection...',
    'Verifying cryptographic keys...',
    'Compiling core modules...',
    'Scanning for network anomalies...',
    'Analyzing data packets...',
    'Encrypting session data...',
    'Defragmenting memory space...',
    'Checking system integrity...',
    'Awaiting protocol handshake...',
    'Decrypting configuration files...',
    'Validating checksums...',
    'Allocating system resources...',
    'Performing integrity checks...',
    'Synchronizing with main server...'
  ];

  // An array of fake log lines for the activity log.
  const logLines = [
    '> systemd start networkd...',
    '[ OK ] Found new protocol stack on iface lo',
    '[ INFO ] Establishing connection to gateway...',
    '> ping -c 4 127.0.0.1',
    '[ OK ] 4 packets transmitted, 4 received',
    '[ INFO ] Syncing with time server ntp.pool.org...',
    '> ssh root@10.0.0.1',
    '[ WARN ] Host key not found, adding to known hosts',
    '[ OK ] Authenticated successfully.',
    '> ls -l /var/log',
    '[ OK ] Directory listing complete.',
    '[ INFO ] Starting log rotation service...',
    '[ OK ] DNS resolution successful for vulnuscan.io',
    '[ OK ] Mounted /dev/sda1 to /mnt/data',
    '[ WARN ] Unhandled exception in process 0x2A1B',
    '[ INFO ] Initiating data stream 0xDEB0...',
    '> netstat -tuln',
    '[ OK ] Listening ports discovered.',
    '[ INFO ] Starting watchdog timer...',
    '[ OK ] All services online.',
    '> service monitor start'
  ];

  // The useEffect hook simulates the continuous loading process.
  useEffect(() => {
    let messageInterval;
    let logInterval;

    // Interval for updating the status message.
    messageInterval = setInterval(() => {
      setStatusMessage(prevMessage => {
        const currentIndex = loadingMessages.indexOf(prevMessage);
        const nextIndex = (currentIndex + 1) % loadingMessages.length;
        return loadingMessages[nextIndex];
      });
    }, 300);

    // Interval for adding new log lines.
    logInterval = setInterval(() => {
      setActivityLog(prevLog => {
        // Get a random log line from the array.
        const randomLine = logLines[Math.floor(Math.random() * logLines.length)];
        const newLog = [...prevLog, randomLine];
        
        // Keep the log at a maximum of 8 lines to create the "rolling" effect.
        if (newLog.length > 8) {
          return newLog.slice(newLog.length - 8);
        }
        return newLog;
      });
    }, 100);

    // Clean up the intervals when the component unmounts.
    return () => {
      clearInterval(messageInterval);
      clearInterval(logInterval);
    };
  }, []);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 text-green-400 font-mono relative overflow-hidden p-4">
      {/* Background Grid Pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,65,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,65,0.03)_1px,transparent_1px)] bg-[size:50px_50px]"></div>

      {/* Main content container */}
      <div className="relative z-10 w-full max-w-xl mx-auto text-center">
        {/* Animated Loader Icon */}
        <div className="flex justify-center mb-8">
          <Loader size={64} strokeWidth={1} className="animate-spin text-green-400" />
        </div>

        {/* Dynamic Status Message */}
        <h1 className="text-xl md:text-2xl font-bold mb-4 text-white">{statusMessage}</h1>

        {/* The new dynamic activity log container */}
        <div className="w-full h-40 bg-black/40 border border-green-400/20 rounded-lg p-4 shadow-inner overflow-hidden">
          <pre className="text-sm text-left leading-tight whitespace-pre-wrap break-words">
            {activityLog.map((line, index) => (
              <div key={index} className="opacity-70 transition-all duration-300 transform translate-y-0">{line}</div>
            ))}
            {/* Blinking cursor for terminal vibe */}
            <span className="animate-pulse">_</span>
          </pre>
        </div>

        {/* Footer Text */}
        <p className="mt-6 text-sm text-gray-400">
          <Code size={16} className="inline mr-2 text-green-400" />
          Preparing a secure environment. Please wait.
        </p>
      </div>
    </div>
  );
}

export default Load;
