import React, { useState } from 'react';

// --- JAVASCRIPT LOGIC REPLICATING parser_v2.py (UPDATED FOR ENRICHMENT) ---

// Helper function to escape double quotes for Splunk/KV output
const escapeQuotes = (value) => {
  if (typeof value === 'string') {
    return value.replace(/"/g, '\\"');
  }
  return value;
};

// 1. SSH LOG PARSING LOGIC
const parseSshLog = (line) => {
  let parsed = null;
  
  // Regex for accepted password
  const acceptedMatch = line.match(/sshd\[(\d+)\]: Accepted password for (\S+) from (\S+)/);
  if (acceptedMatch) {
    parsed = {
      sshd_event: "Accepted password",
      pid: acceptedMatch[1],
      user: acceptedMatch[2],
      src_ip: acceptedMatch[3]
    };
  }

  // Regex for failed password
  const failedMatch = line.match(/sshd\[(\d+)\]: Failed password for (?:invalid user )?(\S+) from (\S+)/);
  if (!parsed && failedMatch) {
    let user = failedMatch[2];
    if (line.includes("invalid user")) {
      user = `invalid user ${user}`;
    }
    parsed = {
      sshd_event: "Failed password",
      pid: failedMatch[1],
      user: user,
      src_ip: failedMatch[3]
    };
  }
  
  // Regex for session opened (using PID is less reliable here, using simple form)
  const sessionOpenedMatch = line.match(/pam_unix\(sshd:session\): session opened for user (\S+)/);
  if (!parsed && sessionOpenedMatch) {
    parsed = {
      sshd_event: "session opened",
      user: sessionOpenedMatch[1],
      service: "sshd"
    };
  }
  
  // Regex for session closed
  const sessionClosedMatch = line.match(/pam_unix\(sshd:session\): session closed for user (\S+)/);
  if (!parsed && sessionClosedMatch) {
    parsed = {
      sshd_event: "session closed",
      user: sessionClosedMatch[1],
      service: "sshd"
    };
  }

  // Fallback for user context in some logs
  const userContextMatch = line.match(/User (.*) logged in/);
  if (!parsed && userContextMatch) {
      parsed = {
          sshd_event: "User login context",
          user: userContextMatch[1],
          service: "sshd"
      };
  }

  return parsed;
};

// 2. HTTP LOG PARSING LOGIC (Common Log Format)
const parseHttpLog = (line) => {
  // Regex for Apache Common Log Format (IP - user [date] "request" status size)
  const httpMatch = line.match(/^(\S+) - (\S+) \[(.+?)\] \"([^\"]+)\" (\d+) (\d+)/);
  if (httpMatch) {
    return {
      src_ip: httpMatch[1],
      ident: httpMatch[2],
      timestamp: httpMatch[3],
      request: httpMatch[4],
      status_code: httpMatch[5],
      size: httpMatch[6]
    };
  }
  return null;
};

// 3. OUTPUT FORMATTING LOGIC
const formatToSplunk = (data) => {
  return Object.entries(data)
    .map(([key, value]) => `${key}="${escapeQuotes(value)}"`) // Corrected: escaped quote within template literal
    .join(', ');
};

const formatToJson = (data) => {
  return JSON.stringify(data);
};

// 4. IP ENRICHMENT LOGIC (Bonus Challenge)

// Cache to store fetched IP data and avoid re-querying (Vibe Hint)
const ipCache = {};

/**
 * Fetches geolocation data for a single IP using a public API.
 * @param {string} ip The IP address to query.
 * @returns {Promise<object>} Enrichment data or a minimal error object.
 */
const fetchEnrichmentData = async (ip) => {
    // Check cache first (Efficiency Vibe)
    if (ipCache[ip]) {
        return ipCache[ip];
    }
    
    // ip-api.com is free and generally CORS-friendly for browser demos
    const url = `http://ip-api.com/json/${ip}?fields=status,country,city,isp,query`;
    
    try {
        const response = await fetch(url);
        const data = await response.json();

        if (data.status === 'success') {
            const enrichment = {
                country: data.country || 'N/A',
                city: data.city || 'N/A',
                isp: data.isp || 'N/A',
                enrichment_status: 'SUCCESS'
            };
            ipCache[ip] = enrichment; // Cache the successful result
            return enrichment;
        } else {
            const enrichment = {
                country: 'Unknown',
                city: 'Unknown',
                enrichment_status: `API_ERROR: ${data.message || 'Failed'}`
            };
            ipCache[ip] = enrichment; // Cache the error result
            return enrichment;
        }
    } catch (e) {
        console.error(`Enrichment failed for ${ip}:`, e);
        const enrichment = {
            country: 'Unknown',
            city: 'Unknown',
            enrichment_status: 'NETWORK_ERROR'
        };
        ipCache[ip] = enrichment; // Cache the network error
        return enrichment;
    }
};

// --- REACT APPLICATION COMPONENT ---

const App = () => {
  const [file, setFile] = useState(null);
  const [format, setFormat] = useState('splunk');
  const [status, setStatus] = useState('Ready to parse log file.');
  const [isParsing, setIsParsing] = useState(false);
  const [enrichmentStatus, setEnrichmentStatus] = useState('');

  const handleFileChange = (event) => {
    const uploadedFile = event.target.files[0];
    if (uploadedFile) {
      setFile(uploadedFile);
      setStatus(`File selected: ${uploadedFile.name}`);
      setEnrichmentStatus('');
    }
  };

  const determineLogType = (firstLine) => {
      if (firstLine.includes("sshd") || firstLine.includes("pam_unix")) {
          return "ssh";
      } 
      // Assuming a common log format starts with an IP address pattern
      const httpPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
      if (httpPattern.test(firstLine)) {
          return "http";
      }
      return "unknown";
  };
  
  const triggerDownload = (content, filename) => {
    // Bonus 1: Prompt the user to download a new file
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const getUniqueSourceIps = (parsedLogs) => {
      const ips = new Set();
      parsedLogs.forEach(log => {
          if (log.src_ip && log.src_ip !== '-') {
              ips.add(log.src_ip);
          }
      });
      return Array.from(ips);
  };

  const handleParse = async () => {
    if (!file) {
      setStatus("Please select a file first.");
      return;
    }

    setIsParsing(true);
    setEnrichmentStatus('');
    setStatus(`1/3: Reading ${file.name}...`);

    try {
      const fileText = await file.text();
      const lines = fileText.split('\n').filter(line => line.trim() !== '');

      if (lines.length === 0) {
        setStatus("Error: The uploaded file is empty.");
        setIsParsing(false);
        return;
      }

      const logType = determineLogType(lines[0]);
      
      if (logType === "unknown") {
        setStatus("Error: Could not determine log type (expected SSH or HTTP).");
        setIsParsing(false);
        return;
      }

      // 2/3: Base Parsing
      let parsedLogs = [];
      const parserFunction = logType === "ssh" ? parseSshLog : parseHttpLog;
      for (const line of lines) {
        const parsedData = parserFunction(line);
        if (parsedData) {
          parsedLogs.push(parsedData);
        }
      }
      
      // 2. Enrichment: Collect Unique IPs
      const uniqueIps = getUniqueSourceIps(parsedLogs);
      
      setEnrichmentStatus(`Starting enrichment for ${uniqueIps.length} unique IP(s)...`);
      
      // Fetch data for all unique IPs concurrently
      const enrichmentPromises = uniqueIps.map(ip => fetchEnrichmentData(ip));
      await Promise.all(enrichmentPromises);
      
      setEnrichmentStatus('Enrichment completed. Merging data...');

      // 3/3: Formatting and Merging (The Vibe Merge)
      let formattedOutput = [];
      const formatFunction = format === "splunk" ? formatToSplunk : formatToJson;
      
      for (const log of parsedLogs) {
          let finalLog = { ...log };
          
          if (log.src_ip) {
              const enrichmentData = ipCache[log.src_ip];
              if (enrichmentData) {
                  // Merge the enrichment data into the log event
                  finalLog = { ...log, ...enrichmentData };
                  delete finalLog.query; // Clean up internal API field
              } 
          }
          
          formattedOutput.push(formatFunction(finalLog));
      }

      const filename = `enriched_logs.${format === 'json' ? 'json' : 'txt'}`;
      const content = formattedOutput.join(format === 'json' ? '\n' : '\n');
      
      triggerDownload(content, filename);

      setStatus(`SUCCESS! Parsed ${parsedLogs.length} events and enriched ${uniqueIps.length} unique IPs. Downloaded ${filename}.`);
      setEnrichmentStatus('');

    } catch (error) {
      setStatus(`An error occurred during processing: ${error.message}`);
      setEnrichmentStatus('');
      console.error(error);
    } finally {
      setIsParsing(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4 sm:p-6 font-sans">
      <script src="https://cdn.tailwindcss.com"></script>
      <div className="w-full max-w-lg bg-white shadow-xl rounded-xl p-6 sm:p-8 border border-gray-200">
        <h1 className="text-3xl font-extrabold text-gray-900 mb-4 text-center">
          Vibe SOC Log Enrichemnt Engine
        </h1>
        <p className="text-center text-sm text-gray-500 mb-6 text-indigo-600 font-medium">
          Part 4: Real-time IP Geolocation Enrichment 🌍
        </p>

        <div className="space-y-6">
          {/* File Upload Field */}
          <div>
            <label htmlFor="file-upload" className="block text-sm font-medium text-gray-700 mb-2">
              1. Choose Log File
            </label>
            <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-dashed rounded-md transition duration-300 ease-in-out hover:border-indigo-400">
              <div className="space-y-1 text-center">
                <svg className="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48" aria-hidden="true">
                  <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3-3m0 0l-3 3" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" />
                </svg>
                <div className="flex text-sm text-gray-600">
                  <label 
                    htmlFor="file-upload"
                    className="relative cursor-pointer bg-white rounded-md font-medium text-indigo-600 hover:text-indigo-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-indigo-500"
                  >
                    <span>Upload a file</span>
                    <input id="file-upload" name="file-upload" type="file" className="sr-only" onChange={handleFileChange} />
                  </label>
                  <p className="pl-1">or drag and drop</p>
                </div>
                {file && <p className="text-xs text-indigo-600 truncate">{file.name}</p>}
                {!file && <p className="text-xs text-gray-500">Max size 5MB</p>}
              </div>
            </div>
          </div>

          {/* Output Format Dropdown */}
          <div>
            <label htmlFor="output-format" className="block text-sm font-medium text-gray-700 mb-2">
              2. Select Output Format
            </label>
            <select
              id="output-format"
              name="output-format"
              value={format}
              onChange={(e) => setFormat(e.target.value)}
              className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm rounded-md shadow-sm"
            >
              <option value="splunk">Splunk Key-Value Pairs (.txt)</option>
              <option value="json">JSON Format (.json)</option>
            </select>
          </div>
          
          {/* Parse Button */}
          <button
            onClick={handleParse}
            disabled={!file || isParsing}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 transition duration-150"
          >
            {isParsing ? (
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
            ) : (
                "3. Enrich & Download Logs"
            )}
          </button>

          {/* Status Message */}
          <div className="mt-4 p-3 rounded-md text-sm bg-indigo-100 text-indigo-700">
            <p className="font-medium">
                {status}
            </p>
            {enrichmentStatus && (
                <p className="text-xs text-indigo-500 mt-1 animate-pulse">
                    {enrichmentStatus}
                </p>
            )}
            {status.startsWith('Error') && (
                <p className="text-sm text-red-700">
                    {status}
                </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
