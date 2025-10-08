import { useState, useEffect, ReactElement } from 'react';
import { Loader, Code } from 'lucide-react';

const Load = (): ReactElement => {
  const [statusMessage, setStatusMessage] = useState<string>('Initializing system...');
  const [activityLog, setActivityLog] = useState<string[]>(['']);

  const loadingMessages: string[] = [
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

  const logLines: string[] = [
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

  useEffect(() => {
    const messageInterval = setInterval(() => {
      setStatusMessage((prevMessage: string) => {
        const currentIndex = loadingMessages.indexOf(prevMessage);
        const nextIndex = (currentIndex + 1) % loadingMessages.length;
        const nextMessage = loadingMessages[nextIndex];
        return nextMessage !== undefined ? nextMessage : prevMessage;
      });
    }, 300);

    const logInterval = setInterval(() => {
      setActivityLog((prevLog: string[]) => {
        const randomIndex = Math.floor(Math.random() * logLines.length);
        const randomLine = logLines[randomIndex];
        const newLog = [...prevLog, randomLine !== undefined ? randomLine : ''];
        
        if (newLog.length > 8) {
          return newLog.slice(newLog.length - 8);
        }
        return newLog;
      });
    }, 100);

    return () => {
      clearInterval(messageInterval);
      clearInterval(logInterval);
    };
  }, [loadingMessages, logLines]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 text-green-400 font-mono relative overflow-hidden p-4">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,65,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,65,0.03)_1px,transparent_1px)] bg-[size:50px_50px]"></div>

      <div className="relative z-10 w-full max-w-xl mx-auto text-center">
        <div className="flex justify-center mb-8">
          <Loader size={64} strokeWidth={1} className="animate-spin text-green-400" />
        </div>

        <h1 className="text-xl md:text-2xl font-bold mb-4 text-white">{statusMessage}</h1>

        <div className="w-full h-40 bg-black/40 border border-green-400/20 rounded-lg p-4 shadow-inner overflow-hidden">
          <pre className="text-sm text-left leading-tight whitespace-pre-wrap break-words">
            {activityLog.map((line: string, index: number) => (
              <div key={index} className="opacity-70 transition-all duration-300 transform translate-y-0">{line}</div>
            ))}
            <span className="animate-pulse">_</span>
          </pre>
        </div>

        <p className="mt-6 text-sm text-gray-400">
          <Code size={16} className="inline mr-2 text-green-400" />
          Preparing a secure environment. Please wait.
        </p>
      </div>
    </div>
  );
};

export default Load;
