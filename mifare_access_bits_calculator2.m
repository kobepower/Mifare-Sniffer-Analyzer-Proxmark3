% MATLAB script to read a Proxmark3 dump (supports Iceman firmware formats: .bin, .mfd, .eml, .txt, .hex)
% For MIFARE Classic cards: Mini (320B), 1K (1024B), 4K (4096B), and hypothetical 8K (8192B).
% Extracts and decodes access bits for each sector.
% Displays permissions for data blocks/groups and trailer, including which keys can be used for read/write/auth.
% Indicates if Key B is readable (and thus cannot be used for authentication).
% Handles large sectors in 4K+ with grouped data blocks.
% ENHANCED: Security scoring, writable block finder, CSV export with color coding
% Usage: Run in MATLAB, select dump file via dialog, or pass filename as argument.
% Example: mifare_access_bits_calculator2('mydump.bin')

function mifare_access_bits_calculator2(varargin)

clc; close all;

% Handle input: dialog or arg
if nargin >= 1 && ischar(varargin{1})
    fname = varargin{1};
else
    [file, path] = uigetfile({'*.bin;*.mfd;*.eml;*.txt;*.hex;*.dump', 'Proxmark dump files'}, 'Select MIFARE Classic dump file');
    if isequal(file, 0)
        fprintf('No file selected. Exiting.\n');
        return;
    end
    fname = fullfile(path, file);
end

fprintf('Reading file: %s\n', fname);

% Read dump
dump = read_dump(fname);

% Detect card type and structure
[card_type, nSectors, sector_starts, is_large] = detect_card_type(numel(dump));

fprintf('Detected: %s (%d bytes, %d sectors)\n', card_type, numel(dump), nSectors);

% Initialize summary data
summary_data = {};
writable_blocks = [];
security_issues = {};
all_perms = {};

% Process each sector
for s = 0:nSectors-1
    sector_start = sector_starts(s+1);
    if is_large(s+1)
        trailer_offset = 240;
        num_data_blocks = 15;
    else
        trailer_offset = 48;
        num_data_blocks = 3;
    end
    trailer_start = sector_start + trailer_offset;
    keyA = dump(trailer_start:trailer_start+5);
    access_bytes = dump(trailer_start+6:trailer_start+8);
    gp_byte = dump(trailer_start+9);
    keyB = dump(trailer_start+10:trailer_start+15);
    
    keyA_hex = sprintf('%02X', keyA);
    keyB_hex = sprintf('%02X', keyB);
    
    fprintf('\n=== Sector %d ===\n', s);
    fprintf('Key A: %s\n', keyA_hex);
    fprintf('Access Bytes: %02X %02X %02X\n', access_bytes);
    fprintf('GP Byte: %02X\n', gp_byte);
    fprintf('Key B: %s\n', keyB_hex);
    
    % Check for weak keys
    if strcmp(keyA_hex, 'FFFFFFFFFFFF')
        security_issues{end+1} = sprintf('Sector %d: Default Key A (FFFFFFFFFFFF)', s);
    end
    if strcmp(keyB_hex, 'FFFFFFFFFFFF')
        security_issues{end+1} = sprintf('Sector %d: Default Key B (FFFFFFFFFFFF)', s);
    end
    
    % Decode access bits
    Cbits = decode_access_bytes(access_bytes);
    
    % Permissions for data blocks/groups
    if is_large(s+1)
        fprintf('\nData Groups Permissions (groups of 5 blocks):\n');
        blocks_per_group = 5;
    else
        fprintf('\nData Blocks Permissions:\n');
        blocks_per_group = 1;
    end
    num_data_sets = 3;
    
    for g = 0:num_data_sets-1
        c1 = Cbits(g+1,1); c2 = Cbits(g+1,2); c3 = Cbits(g+1,3);
        perms = interpret_data_permissions(c1, c2, c3);
        
        if is_large(s+1)
            group_blocks = sprintf('%d-%d', g*blocks_per_group, (g+1)*blocks_per_group-1);
            fprintf('Group %d (blocks %s) (C1%d %d C2%d %d C3%d %d): %s\n', g, group_blocks, g, c1, g, c2, g, c3, perms);
        else
            block_num = s*4 + g;
            fprintf('Block %d (C1%d %d C2%d %d C3%d %d): %s\n', block_num, g, c1, g, c2, g, c3, perms);
        end
        
        detail = compute_data_perms_detail(c1, c2, c3);
        fprintf('  Read: %s\n', get_key_str(detail.read_A, detail.read_B));
        fprintf('  Write: %s\n', get_key_str(detail.write_A, detail.write_B));
        fprintf('  Increment: %s\n', get_key_str(detail.inc_A, detail.inc_B));
        fprintf('  Dec/Trans/Rest: %s\n', get_key_str(detail.dec_A, detail.dec_B));
        
        % Store permissions for summary
        if is_large(s+1)
            for gb = 0:blocks_per_group-1
                actual_block = s*4 + g*blocks_per_group + gb;
                all_perms{end+1} = struct('sector', s, 'block', actual_block, ...
                    'can_read', detail.read_A || detail.read_B, ...
                    'can_write', detail.write_A || detail.write_B, ...
                    'keyA_hex', keyA_hex, 'keyB_hex', keyB_hex, ...
                    'detail', detail);
            end
        else
            actual_block = s*4 + g;
            all_perms{end+1} = struct('sector', s, 'block', actual_block, ...
                'can_read', detail.read_A || detail.read_B, ...
                'can_write', detail.write_A || detail.write_B, ...
                'keyA_hex', keyA_hex, 'keyB_hex', keyB_hex, ...
                'detail', detail);
        end
        
        % Track writable blocks
        if detail.write_A || detail.write_B
            if is_large(s+1)
                for gb = 0:blocks_per_group-1
                    writable_blocks(end+1) = s*4 + g*blocks_per_group + gb;
                end
            else
                writable_blocks(end+1) = s*4 + g;
            end
        end
        
        % Check for transport config
        if c1==0 && c2==0 && c3==0
            security_issues{end+1} = sprintf('Sector %d Block %d: Transport configuration (no security)', s, g);
        end
    end
    
    % Permissions for trailer
    c1 = Cbits(4,1); c2 = Cbits(4,2); c3 = Cbits(4,3);
    perms = interpret_trailer_permissions(c1, c2, c3);
    fprintf('\nTrailer Permissions (C13 %d C23 %d C33 %d):\n%s\n', c1, c2, c3, perms);
    detail = compute_trailer_perms_detail(c1, c2, c3);
    
    % Check if Key B is readable
    keyB_readable_A = detail.keyB_read_A;
    keyB_readable_B = detail.keyB_read_B;
    if keyB_readable_A || keyB_readable_B
        readable_with = get_key_str(keyB_readable_A, keyB_readable_B);
        fprintf('Key B is readable (with %s) (treated as data), cannot be used for authentication.\n', readable_with);
        auth_keys = 'Only Key A';
        security_issues{end+1} = sprintf('Sector %d: Key B is readable (weak configuration)', s);
    else
        fprintf('Key B is not readable, can be used for authentication.\n');
        auth_keys = 'Key A or Key B';
    end
    fprintf('Possible authentication keys: %s\n', auth_keys);
    
    fprintf('Key A Write: %s\n', get_key_str(detail.keyA_write_A, detail.keyA_write_B));
    fprintf('Access Bits Read: %s\n', get_key_str(detail.access_read_A, detail.access_read_B));
    fprintf('Access Bits Write: %s\n', get_key_str(detail.access_write_A, detail.access_write_B));
    fprintf('Key B Write: %s\n', get_key_str(detail.keyB_write_A, detail.keyB_write_B));
    
    % Add to summary
    summary_data{end+1} = struct('sector', s, 'keyA', keyA_hex, 'keyB', keyB_hex, ...
        'access_bytes', sprintf('%02X%02X%02X', access_bytes), ...
        'auth_keys', auth_keys);
end

fprintf('\n========================================\n');
fprintf('ANALYSIS SUMMARY\n');
fprintf('========================================\n');

% Security Score
security_score = calculate_security_score(summary_data, security_issues, nSectors);
fprintf('\n=== SECURITY SCORE: %d/100 ===\n', security_score);
if security_score >= 80
    fprintf('Status: EXCELLENT - Card is well secured\n');
elseif security_score >= 60
    fprintf('Status: GOOD - Card has reasonable security\n');
elseif security_score >= 40
    fprintf('Status: FAIR - Card has weak security\n');
else
    fprintf('Status: POOR - Card is highly vulnerable\n');
end

% Security Issues
if ~isempty(security_issues)
    fprintf('\n=== SECURITY ISSUES (%d found) ===\n', length(security_issues));
    for i = 1:length(security_issues)
        fprintf('[!] %s\n', security_issues{i});
    end
else
    fprintf('\n[OK] No major security issues detected\n');
end

% Writable Blocks
fprintf('\n=== WRITABLE BLOCKS (%d total) ===\n', length(writable_blocks));
if ~isempty(writable_blocks)
    fprintf('Blocks you can modify: ');
    fprintf('%d ', writable_blocks);
    fprintf('\n');
    fprintf('(These blocks have write permissions with available keys)\n');
else
    fprintf('No easily writable blocks found.\n');
end

% Find interesting data blocks
interesting_blocks = find_interesting_blocks(dump, all_perms, nSectors);
if ~isempty(interesting_blocks)
    fprintf('\n=== INTERESTING DATA BLOCKS (non-zero, writable) ===\n');
    for i = 1:length(interesting_blocks)
        ib = interesting_blocks(i);
        fprintf('Block %d (Sector %d): Contains data and is writable\n', ib.block, ib.sector);
    end
end

% Export to CSV
fprintf('\n=== EXPORTING TO CSV ===\n');
[fpath, fbase, ~] = fileparts(fname);
csv_filename = fullfile(fpath, [fbase '_analysis.csv']);
export_to_csv(csv_filename, all_perms, summary_data);
fprintf('CSV exported to: %s\n', csv_filename);

% Export to HTML
fprintf('\n=== EXPORTING TO HTML ===\n');
html_filename = fullfile(fpath, [fbase '_analysis.html']);
export_to_html(html_filename, all_perms, summary_data, security_score, security_issues);
fprintf('HTML report exported to: %s\n', html_filename);

fprintf('\nAnalysis complete.\n');

end

function score = calculate_security_score(summary_data, security_issues, nSectors)
score = 100;
default_key_count = 0;
for i = 1:length(summary_data)
    if strcmp(summary_data{i}.keyA, 'FFFFFFFFFFFF')
        default_key_count = default_key_count + 1;
    end
    if strcmp(summary_data{i}.keyB, 'FFFFFFFFFFFF')
        default_key_count = default_key_count + 1;
    end
end
score = score - (default_key_count * 2);
score = score - (length(security_issues) * 3);
custom_key_sectors = 0;
for i = 1:length(summary_data)
    if ~strcmp(summary_data{i}.keyA, 'FFFFFFFFFFFF') && ~strcmp(summary_data{i}.keyB, 'FFFFFFFFFFFF')
        custom_key_sectors = custom_key_sectors + 1;
    end
end
bonus = (custom_key_sectors / nSectors) * 20;
score = score + bonus;
score = max(0, min(100, round(score)));
end

function interesting = find_interesting_blocks(dump, all_perms, nSectors)
interesting = [];
for i = 1:length(all_perms)
    perm = all_perms{i};
    block_num = perm.block;
    if mod(block_num, 4) == 3
        continue;
    end
    block_start = block_num * 16 + 1;
    if block_start + 15 > length(dump)
        continue;
    end
    block_data = dump(block_start:block_start+15);
    if any(block_data ~= 0)
        if perm.can_write
            interesting(end+1).block = block_num;
            interesting(end).sector = perm.sector;
            interesting(end).data = block_data;
        end
    end
end
end

function export_to_csv(filename, all_perms, summary_data)
fid = fopen(filename, 'w');
fprintf(fid, 'Sector,Block,Can Read,Can Write,Read With,Write With,Key A,Key B,Security Level\n');
for i = 1:length(all_perms)
    perm = all_perms{i};
    read_str = get_key_str(perm.detail.read_A, perm.detail.read_B);
    write_str = get_key_str(perm.detail.write_A, perm.detail.write_B);
    if perm.can_write
        security = 'LOW';
    elseif perm.can_read
        security = 'MEDIUM';
    else
        security = 'HIGH';
    end
    fprintf(fid, '%d,%d,%s,%s,%s,%s,%s,%s,%s\n', ...
        perm.sector, perm.block, ...
        bool2str(perm.can_read), bool2str(perm.can_write), ...
        read_str, write_str, ...
        perm.keyA_hex, perm.keyB_hex, security);
end
fclose(fid);
end

function export_to_html(filename, all_perms, summary_data, security_score, security_issues)
fid = fopen(filename, 'w');
fprintf(fid, '<!DOCTYPE html>\n<html>\n<head>\n');
fprintf(fid, '<title>MIFARE Classic Analysis Report</title>\n');
fprintf(fid, '<style>\n');
fprintf(fid, 'body { font-family: Arial, sans-serif; margin: 20px; }\n');
fprintf(fid, 'h1 { color: #333; }\n');
fprintf(fid, 'table { border-collapse: collapse; width: 100%%; margin-top: 20px; }\n');
fprintf(fid, 'th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n');
fprintf(fid, 'th { background-color: #4CAF50; color: white; }\n');
fprintf(fid, '.writable { background-color: #90EE90; }\n');
fprintf(fid, '.readonly { background-color: #FFB6C1; }\n');
fprintf(fid, '.no-access { background-color: #FF6347; color: white; }\n');
fprintf(fid, '.score-good { color: green; font-weight: bold; }\n');
fprintf(fid, '.score-fair { color: orange; font-weight: bold; }\n');
fprintf(fid, '.score-poor { color: red; font-weight: bold; }\n');
fprintf(fid, '.issue { color: #D8000C; background-color: #FFD2D2; padding: 5px; margin: 5px 0; }\n');
fprintf(fid, '</style>\n</head>\n<body>\n');
fprintf(fid, '<h1>MIFARE Classic Analysis Report</h1>\n');
fprintf(fid, '<h2>Security Score: <span class="score-');
if security_score >= 60
    fprintf(fid, 'good');
elseif security_score >= 40
    fprintf(fid, 'fair');
else
    fprintf(fid, 'poor');
end
fprintf(fid, '">%d/100</span></h2>\n', security_score);
if ~isempty(security_issues)
    fprintf(fid, '<h3>Security Issues (%d)</h3>\n', length(security_issues));
    for i = 1:length(security_issues)
        fprintf(fid, '<div class="issue">[!] %s</div>\n', security_issues{i});
    end
end
fprintf(fid, '<h3>Block Permissions</h3>\n');
fprintf(fid, '<table>\n');
fprintf(fid, '<tr><th>Sector</th><th>Block</th><th>Read</th><th>Write</th><th>Read With</th><th>Write With</th><th>Status</th></tr>\n');
for i = 1:length(all_perms)
    perm = all_perms{i};
    if perm.can_write
        row_class = 'writable';
        status = 'WRITABLE';
    elseif perm.can_read
        row_class = 'readonly';
        status = 'READ-ONLY';
    else
        row_class = 'no-access';
        status = 'NO ACCESS';
    end
    read_str = get_key_str(perm.detail.read_A, perm.detail.read_B);
    write_str = get_key_str(perm.detail.write_A, perm.detail.write_B);
    fprintf(fid, '<tr class="%s"><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n', ...
        row_class, perm.sector, perm.block, ...
        bool2str(perm.can_read), bool2str(perm.can_write), ...
        read_str, write_str, status);
end
fprintf(fid, '</table>\n');
fprintf(fid, '</body>\n</html>\n');
fclose(fid);
end

function str = bool2str(val)
if val
    str = 'YES';
else
    str = 'NO';
end
end

function [card_type, nSectors, sector_starts, is_large] = detect_card_type(dump_size)
sector_starts = [];
is_large = [];
if dump_size == 320
    card_type = 'MIFARE Classic Mini (S20)';
    nSectors = 5;
    sector_sizes = repmat(64, 1, nSectors);
    is_large = false(1, nSectors);
elseif dump_size == 1024
    card_type = 'MIFARE Classic 1K (S50)';
    nSectors = 16;
    sector_sizes = repmat(64, 1, nSectors);
    is_large = false(1, nSectors);
elseif dump_size == 4096
    card_type = 'MIFARE Classic 4K (S70)';
    nSectors = 40;
    sector_sizes = [repmat(64, 1, 32) repmat(256, 1, 8)];
    is_large = [false(1,32) true(1,8)];
elseif dump_size == 8192
    card_type = 'MIFARE Classic 8K (non-standard)';
    nSectors = 48;
    sector_sizes = [repmat(64, 1, 32) repmat(256, 1, 16)];
    is_large = [false(1,32) true(1,16)];
else
    error('Unsupported dump size %d bytes. Supported: 320 (Mini), 1024 (1K), 4096 (4K), 8192 (8K non-std).', dump_size);
end
sector_starts = zeros(1, nSectors);
current = 1;
for s = 1:nSectors
    sector_starts(s) = current;
    current = current + sector_sizes(s);
end
end

function data = read_dump(fname)
[~,~,ext] = fileparts(fname);
binary_exts = {'.bin', '.mfd', '.dump'};
text_exts = {'.eml', '.txt', '.hex'};
if any(strcmpi(ext, binary_exts))
    fid = fopen(fname, 'rb');
    data = fread(fid, Inf, 'uint8')';
    fclose(fid);
elseif any(strcmpi(ext, text_exts))
    s = fileread(fname);
    data = parse_hex_text(s);
else
    error('Unsupported file extension: %s. Supported: .bin, .mfd, .eml, .txt, .hex, .dump', ext);
end
if numel(data) == 0
    error('Empty dump file.');
end
end

function data = parse_hex_text(s)
data = [];
s = strrep(s, sprintf('\r\n'), sprintf('\n'));
lines = strsplit(s, '\n');
for i = 1:numel(lines)
    L = strtrim(lines{i});
    if isempty(L), continue; end
    L = regexprep(L, '^(\+|\-)?0x?[0-9A-Fa-f]+[:\s]*', '');
    L = regexprep(L, '[^0-9A-Fa-f\s]', '');
    if contains(L, ' ')
        tokens = strsplit(L);
    else
        tokens = regexp(L, '.{2}', 'match');
    end
    if ~isempty(tokens)
        bytes = uint8(hex2dec(tokens));
        data = [data bytes];
    end
end
if isempty(data)
    error('No hex data found in file.');
end
end

function Cbits = decode_access_bytes(access_bytes)
b6 = access_bytes(1);
b7 = access_bytes(2);
b8 = access_bytes(3);
inv_low6 = bitxor(bitand(b6, 15), 15);
c1_temp = bitget(inv_low6, 4:-1:1);
c1 = fliplr(c1_temp);
inv_high6 = bitxor(bitshift(bitand(b6, 240), -4), 15);
c2_temp = bitget(inv_high6, 4:-1:1);
c2 = fliplr(c2_temp);
inv_low7 = bitxor(bitand(b7, 15), 15);
c3_temp = bitget(inv_low7, 4:-1:1);
c3 = fliplr(c3_temp);
Cbits = [c1' c2' c3'];
end

function str = interpret_data_permissions(c1, c2, c3)
idx = bin2dec([num2str(c1) num2str(c2) num2str(c3)]);
switch idx
    case 0, str = 'transport configuration: read/write/increment/decrement,transfer,restore with key A|B';
    case 1, str = 'read/write block: read with key A|B, never write/increment/decrement,transfer,restore';
    case 2, str = 'read/write block: read with key A|B, write with key B, never increment/decrement,transfer,restore';
    case 3, str = 'value block: read with key A|B, write/increment with key B, decrement,transfer,restore with key A|B';
    case 4, str = 'value block: read with key A|B, never write/increment, decrement,transfer,restore with key A|B';
    case 5, str = 'read/write block: read/write with key B, never increment/decrement,transfer,restore';
    case 6, str = 'read/write block: read with key B, never write/increment/decrement,transfer,restore';
    case 7, str = 'read/write block: never read/write/increment/decrement,transfer,restore';
    otherwise, str = 'invalid';
end
end

function str = interpret_trailer_permissions(c1, c2, c3)
idx = bin2dec([num2str(c1) num2str(c2) num2str(c3)]);
switch idx
    case 0, str = 'KeyA: never read, write with key A; Access: read with key A, never write; KeyB: read with key A, write with key A | Key B may be read';
    case 1, str = 'KeyA: never read/write; Access: read with key A, never write; KeyB: read with key A, never write | Key B may be read';
    case 2, str = 'KeyA: never read, write with key B; Access: read with key A|B, never write; KeyB: never read, write with key B | Key B may be read';
    case 3, str = 'KeyA: never read/write; Access: read with key A|B, never write; KeyB: never read/write';
    case 4, str = 'KeyA: never read, write with key A; Access: read with key A, write with key A; KeyB: read with key A, write with key A | Key B may be read, transport config';
    case 5, str = 'KeyA: never read, write with key B; Access: read with key A|B, write with key B; KeyB: never read, write with key B';
    case 6, str = 'KeyA: never read/write; Access: read with key A|B, write with key B; KeyB: never read/write';
    case 7, str = 'KeyA: never read/write; Access: read with key A|B, never write; KeyB: never read/write';
    otherwise, str = 'invalid';
end
end

function detail = compute_data_perms_detail(c1, c2, c3)
idx = bin2dec([num2str(c1) num2str(c2) num2str(c3)]);
switch idx
    case 0
        detail.read_A = true; detail.read_B = true;
        detail.write_A = true; detail.write_B = true;
        detail.inc_A = true; detail.inc_B = true;
        detail.dec_A = true; detail.dec_B = true;
    case 1
        detail.read_A = true; detail.read_B = true;
        detail.write_A = false; detail.write_B = false;
        detail.inc_A = false; detail.inc_B = false;
        detail.dec_A = false; detail.dec_B = false;
    case 2
        detail.read_A = true; detail.read_B = true;
        detail.write_A = false; detail.write_B = true;
        detail.inc_A = false; detail.inc_B = false;
        detail.dec_A = false; detail.dec_B = false;
    case 3
        detail.read_A = true; detail.read_B = true;
        detail.write_A = false; detail.write_B = true;
        detail.inc_A = false; detail.inc_B = true;
        detail.dec_A = true; detail.dec_B = true;
    case 4
        detail.read_A = true; detail.read_B = true;
        detail.write_A = false; detail.write_B = false;
        detail.inc_A = false; detail.inc_B = false;
        detail.dec_A = true; detail.dec_B = true;
    case 5
        detail.read_A = false; detail.read_B = true;
        detail.write_A = false; detail.write_B = true;
        detail.inc_A = false; detail.inc_B = false;
        detail.dec_A = false; detail.dec_B = false;
    case 6
        detail.read_A = false; detail.read_B = true;
        detail.write_A = false; detail.write_B = false;
        detail.inc_A = false; detail.inc_B = false;
        detail.dec_A = false; detail.dec_B = false;
    case 7
        detail.read_A = false; detail.read_B = false;
        detail.write_A = false; detail.write_B = false;
        detail.inc_A = false; detail.inc_B = false;
        detail.dec_A = false; detail.dec_B = false;
    otherwise
        detail = struct('read_A', false, 'read_B', false, 'write_A', false, 'write_B', false, 'inc_A', false, 'inc_B', false, 'dec_A', false, 'dec_B', false);
end
end

function detail = compute_trailer_perms_detail(c1, c2, c3)
idx = bin2dec([num2str(c1) num2str(c2) num2str(c3)]);
switch idx
    case 0
        detail.keyA_read = false;
        detail.keyA_write_A = true; detail.keyA_write_B = false;
        detail.access_read_A = true; detail.access_read_B = false;
        detail.access_write_A = false; detail.access_write_B = false;
        detail.keyB_read_A = true; detail.keyB_read_B = false;
        detail.keyB_write_A = true; detail.keyB_write_B = false;
    case 1
        detail.keyA_read = false;
        detail.keyA_write_A = false; detail.keyA_write_B = false;
        detail.access_read_A = true; detail.access_read_B = false;
        detail.access_write_A = false; detail.access_write_B = false;
        detail.keyB_read_A = true; detail.keyB_read_B = false;
        detail.keyB_write_A = false; detail.keyB_write_B = false;
    case 2
        detail.keyA_read = false;
        detail.keyA_write_A = false; detail.keyA_write_B = true;
        detail.access_read_A = true; detail.access_read_B = true;
        detail.access_write_A = false; detail.access_write_B = false;
        detail.keyB_read_A = true; detail.keyB_read_B = false;
        detail.keyB_write_A = false; detail.keyB_write_B = true;
    case 3
        detail.keyA_read = false;
        detail.keyA_write_A = false; detail.keyA_write_B = false;
        detail.access_read_A = true; detail.access_read_B = true;
        detail.access_write_A = false; detail.access_write_B = false;
        detail.keyB_read_A = false; detail.keyB_read_B = false;
        detail.keyB_write_A = false; detail.keyB_write_B = false;
    case 4
        detail.keyA_read = false;
        detail.keyA_write_A = true; detail.keyA_write_B = false;
        detail.access_read_A = true; detail.access_read_B = true;
        detail.access_write_A = true; detail.access_write_B = false;
        detail.keyB_read_A = true; detail.keyB_read_B = false;
        detail.keyB_write_A = true; detail.keyB_write_B = false;
    case 5
        detail.keyA_read = false;
        detail.keyA_write_A = false; detail.keyA_write_B = true;
        detail.access_read_A = true; detail.access_read_B = true;
        detail.access_write_A = false; detail.access_write_B = true;
        detail.keyB_read_A = false; detail.keyB_read_B = false;
        detail.keyB_write_A = false; detail.keyB_write_B = true;
    case 6
        detail.keyA_read = false;
        detail.keyA_write_A = false; detail.keyA_write_B = false;
        detail.access_read_A = true; detail.access_read_B = true;
        detail.access_write_A = false; detail.access_write_B = true;
        detail.keyB_read_A = false; detail.keyB_read_B = false;
        detail.keyB_write_A = false; detail.keyB_write_B = false;
    case 7
        detail.keyA_read = false;
        detail.keyA_write_A = false; detail.keyA_write_B = false;
        detail.access_read_A = true; detail.access_read_B = true;
        detail.access_write_A = false; detail.access_write_B = false;
        detail.keyB_read_A = false; detail.keyB_read_B = false;
        detail.keyB_write_A = false; detail.keyB_write_B = false;
    otherwise
        detail = struct('keyA_read', false, 'keyA_write_A', false, 'keyA_write_B', false, 'access_read_A', false, 'access_read_B', false, 'access_write_A', false, 'access_write_B', false, 'keyB_read_A', false, 'keyB_read_B', false, 'keyB_write_A', false, 'keyB_write_B', false);
end
end

function str = get_key_str(with_A, with_B)
if with_A && with_B
    str = 'Key A or B';
elseif with_A
    str = 'Key A';
elseif with_B
    str = 'Key B';
else
    str = 'Never';
end
end