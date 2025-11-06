% MIFARE Trace Parser
% Extracts keys, UIDs, and authentication data from Proxmark3 trace files

function parseMifareTrace(filename)
    disp('Function started...');  % Debug: Confirm execution begins

    % If no filename provided, try file dialog first, then fallback to prompt
    if nargin < 1
        try
            [file, path] = uigetfile('*.*', 'Select the trace file');
            if isequal(file, 0)
                disp('No file selected via dialog. Falling back to text prompt.');
                filename = input('Enter the trace file name (or full path): ', 's');
                if isempty(filename)
                    error('No file name provided.');
                end
            else
                filename = fullfile(path, file);
            end
        catch
            disp('File dialog failed. Using text prompt instead.');
            filename = input('Enter the trace file name (or full path): ', 's');
            if isempty(filename)
                error('No file name provided.');
            end
        end
    end

    disp(['Attempting to open file: ' filename]);  % Debug: Show file name

    % Read the trace file
    fid = fopen(filename, 'r');
    if fid == -1
        error('Cannot open file: %s', filename);
    end
    
    lines = {};
    line = fgetl(fid);
    while ischar(line)
        lines{end+1} = line;
        line = fgetl(fid);
    end
    fclose(fid);
    
    % Storage for extracted data
    keys = {};
    uids = {};
    blocks_read = {};
    
    fprintf('\n=== MIFARE TRACE ANALYSIS ===\n\n');
    
    % Parse each line
    for i = 1:length(lines)
        line = lines{i};
        
        % Extract UIDs
        if contains(line, 'uid:')
            uid_match = regexp(line, 'uid:([0-9a-f]+)', 'tokens');
            if ~isempty(uid_match)
                uid = uid_match{1}{1};
                if ~ismember(uid, uids)
                    uids{end+1} = uid;
                    fprintf('Found UID: %s\n', upper(uid));
                end
            end
        end
        
        % Extract keys
        if contains(line, 'key ')
            key_match = regexp(line, 'key ([0-9a-f]+)', 'tokens');
            if ~isempty(key_match)
                key = key_match{1}{1};
                if ~ismember(key, keys)
                    keys{end+1} = key;
                    fprintf('Found Key: %s\n', upper(key));
                end
            end
        end
        
        % Extract PRNG status
        if contains(line, 'prng')
            fprintf('PRNG Status: %s\n', strtrim(line));
        end
        
        % Extract block reads
        if contains(line, 'READBLOCK')
            block_match = regexp(line, 'READBLOCK\((\d+)\)', 'tokens');
            if ~isempty(block_match)
                block_num = block_match{1}{1};
                % Look for decrypted data in next line
                if i+1 <= length(lines)
                    next_line = lines{i+1};
                    if contains(next_line, '*')
                        data_match = regexp(next_line, '\|\s*([0-9A-F\s]+)\|', 'tokens');
                        if ~isempty(data_match)
                            data = strtrim(data_match{1}{1});
                            fprintf('\nBlock %s Data: %s\n', block_num, data);
                            blocks_read{end+1} = struct('block', block_num, 'data', data);
                        end
                    end
                end
            end
        end
    end
    
    % Summary
    fprintf('\n=== SUMMARY ===\n');
    fprintf('Total UIDs found: %d\n', length(uids));
    fprintf('Total Keys found: %d\n', length(keys));
    fprintf('Total Blocks read: %d\n', length(blocks_read));
    
    fprintf('\n=== ALL KEYS ===\n');
    for i = 1:length(keys)
        fprintf('Key %d: %s\n', i, upper(keys{i}));
    end
    
    fprintf('\n=== ALL UIDs ===\n');
    for i = 1:length(uids)
        fprintf('UID %d: %s\n', i, upper(uids{i}));
    end
    
    disp('Function completed.');  % Debug: Confirm end
end