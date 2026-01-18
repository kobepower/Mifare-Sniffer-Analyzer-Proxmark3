% analyze_proxmark_dump.m (Enhanced with UID decoder, ASCII extraction, value block detection, access bit validation)
% Usage: run this script in MATLAB. Select 1 or 2 files (imhex text or raw .bin) via dialog or pass as args.
% Supports MIFARE Classic 1K (1024 bytes, 16 sectors), 4K (4096 bytes, 40 sectors), and DESFire (variable size, app/file-based).
% Produces heatmap (with trailer/app overlay), entropy plot (with flags), suspicious blocks heatmap (Classic), ascii preview,
% key extraction with access bits decoding/GP/full perms_detail (Classic) or app/file listing (DESFire), sector-aware diffs, and optional CSV exports.
% NEW: UID decoder, ASCII string extraction, value block detection, access bit validation
% Assumes decrypted MIFARE Classic/DESFire dumps for extraction. Supports drag-and-drop/batch mode.
% Optional: [out_struct] = analyze_proxmark_dump(..., 'return_struct', true) -> returns struct array (sectors for Classic, apps for DESFire).
% Optional: analyze_proxmark_dump(..., 'csvout', 'C:\tmp') -> auto-export CSVs to folder.
function [varargout] = analyze_proxmark_dump_claude_NEW(varargin)
clc; close all;

% Parse options (return_struct, csvout)
p = inputParser;
addParameter(p, 'return_struct', false, @islogical);
addParameter(p, 'csvout', '', @ischar);

% Count non-option arguments
numArgs = nargin;
optStartIdx = numArgs + 1;
for i = 1:nargin
    if ischar(varargin{i}) && (strcmp(varargin{i}, 'return_struct') || strcmp(varargin{i}, 'csvout'))
        optStartIdx = i;
        break;
    end
end

if optStartIdx <= nargin
    parse(p, varargin{optStartIdx:end});
else
    parse(p);
end

return_struct = p.Results.return_struct;
csvout = p.Results.csvout;
auto_export = ~isempty(csvout);
if auto_export && ~isfolder(csvout)
    mkdir(csvout);
end

% Handle input: dialog or args (batch/drag-drop)
if nargin >= 1 && optStartIdx > 1
    files = varargin(1:min(optStartIdx-1, 2));
    path = '';
    interactive = false;
else
    [files, path] = uigetfile({'*.txt;*.imhex;*.bin;*.hex;*.dump;*.*','Imhex or binary files'}, ...
        'Select 1 or 2 proxmark dump files','MultiSelect','on');
    if isequal(files,0)
        fprintf('No file selected. Exiting.\n');
        return;
    end
    if ischar(files)
        files = {files};
    end
    interactive = true;
end

nFiles = numel(files);
if nFiles > 2
    fprintf('Please select at most 2 files. Exiting.\n');
    return;
end

dumps = cell(1,nFiles);
for k = 1:nFiles
    if ~isempty(path)
        fname = fullfile(path, files{k});
    else
        fname = files{k}; % Assume full path if batch
    end
    fprintf('Reading file: %s\n', fname);
    dumps{k} = read_dump_guess_format(fname);
end

out_struct = cell(1,nFiles);  % For return (per file)

% Process each file
for k = 1:nFiles
    dump = dumps{k};
    dump_size = numel(dump);
    card_type = detect_card_type(dump);
    fprintf('\n========================================\n');
    fprintf('FILE %d: %s\n', k, files{k});
    fprintf('========================================\n');
    fprintf('Detected %s (%d bytes)\n', card_type, dump_size);
    
    if strcmp(card_type, 'MIFARE Classic 1K')
        nSectors = 16;
        [keys, access_triples, gp_bytes, sectors] = extract_mifare_keys(dump, nSectors, '1K');
        out_struct{k} = sectors;
        
        % NEW: Decode UID from sector 0
        uid_info = decode_uid(sectors(1).blockData(1,:));
        fprintf('\n=== UID INFORMATION ===\n');
        fprintf('UID: %s\n', uid_info.uid_hex);
        fprintf('UID Type: %s\n', uid_info.uid_type);
        fprintf('Manufacturer: %s\n', uid_info.manufacturer);
        if uid_info.bcc_valid
            fprintf('BCC: %02X (valid)\n', uid_info.bcc);
        else
            fprintf('BCC: %02X (INVALID - should be %02X)\n', uid_info.bcc, uid_info.bcc_calculated);
        end
        fprintf('SAK: %02X\n', uid_info.sak);
        fprintf('ATQA: %02X %02X\n', uid_info.atqa(1), uid_info.atqa(2));
        
        % NEW: Extract ASCII strings
        ascii_strings = extract_ascii_strings(dump);
        
        % NEW: Detect value blocks
        value_blocks = detect_value_blocks(sectors);
        
        display_sectors_detailed(sectors, keys, access_triples, gp_bytes, ascii_strings, value_blocks);
        
    elseif strcmp(card_type, 'MIFARE Classic 4K')
        nSectors = 40;
        [keys, access_triples, gp_bytes, sectors] = extract_mifare_keys(dump, nSectors, '4K');
        out_struct{k} = sectors;
        
        % NEW: Decode UID
        uid_info = decode_uid(sectors(1).blockData(1,:));
        fprintf('\n=== UID INFORMATION ===\n');
        fprintf('UID: %s\n', uid_info.uid_hex);
        fprintf('UID Type: %s\n', uid_info.uid_type);
        fprintf('Manufacturer: %s\n', uid_info.manufacturer);
        if uid_info.bcc_valid
            fprintf('BCC: %02X (valid)\n', uid_info.bcc);
        else
            fprintf('BCC: %02X (INVALID - should be %02X)\n', uid_info.bcc, uid_info.bcc_calculated);
        end
        fprintf('SAK: %02X\n', uid_info.sak);
        fprintf('ATQA: %02X %02X\n', uid_info.atqa(1), uid_info.atqa(2));
        
        % NEW: Extract ASCII strings
        ascii_strings = extract_ascii_strings(dump);
        
        % NEW: Detect value blocks
        value_blocks = detect_value_blocks(sectors);
        
        display_sectors_detailed(sectors, keys, access_triples, gp_bytes, ascii_strings, value_blocks);
        
    elseif strcmp(card_type, 'MIFARE DESFire')
        apps = parse_desfire(dump);
        out_struct{k} = apps;
        display_desfire(apps);
    else
        fprintf('Unsupported card type (size %d). Skipping extraction.\n', dump_size);
        continue;
    end
end

% Make rows of 16 bytes for visualization
bytesPerRow = 16;
mats = cellfun(@(d) reshape_for_rows(d, bytesPerRow), dumps, 'UniformOutput', false);

% Figure 1: heatmap of byte values for first file, with trailer overlay
figure('Name','Byte Heatmap (file 1)','NumberTitle','off');
imagesc(mats{1});
axis tight;
colorbar;
xlabel('Byte index (0..15)');
ylabel('Row (block)');
title(sprintf('Heatmap: %s', files{1}), 'Interpreter', 'none');

% Overlay sector trailers (blocks 3,7,11,... per sector)
if strcmp(card_type, 'MIFARE Classic 1K') || strcmp(card_type, 'MIFARE Classic 4K')
    trailer_map = zeros(size(mats{1}));
    for s = 1:nSectors
        trailer_row = (s-1)*4 + 4; % Block 3 per sector
        if trailer_row <= size(mats{1},1)
            trailer_map(trailer_row, :) = 1;
        end
    end
    hold on;
    h = imagesc(trailer_map, 'AlphaData', 0.3 * trailer_map);
    caxis([0 1]);
    colormap(gca, [1 1 1; 1 0 0]); % White bg, red overlay
    hold off;
    fprintf('\nTrailer overlay added to heatmap.\n');
end

% ASCII preview of first file (first 40 rows)
fprintf('\n========================================\n');
fprintf('ASCII PREVIEW (first 40 blocks)\n');
fprintf('========================================\n');
preview_ascii(mats{1}, 40);

% Entropy plot for first file, flag suspicious blocks (all 0x00 or 0xFF)
Hvals = arrayfun(@(r) block_entropy(mats{1}(r,:)), 1:size(mats{1},1));
figure('Name','Per-block entropy','NumberTitle','off');
plot(Hvals, '-o');
grid on;
xlabel('Block index');
ylabel('Entropy (bits)');
title('Per-block entropy (file 1). Low values often = structured data');

fprintf('\n========================================\n');
fprintf('ENTROPY ANALYSIS\n');
fprintf('========================================\n');
suspicious = find(Hvals < 0.1);  % Threshold for near-zero entropy (all same byte)
if ~isempty(suspicious)
    fprintf('Suspicious blocks (entropy < 0.1):\n');
    for idx = suspicious(:)'
        if all(mats{1}(idx,:) == 0)
            fprintf(' [!] Block %d: All 0x00 (possible wipe/empty block)\n', idx-1);
        elseif all(mats{1}(idx,:) == 255)
            fprintf(' [!] Block %d: All 0xFF (possible wipe/corruption)\n', idx-1);
        else
            fprintf(' [!] Block %d: Low entropy (repeated pattern)\n', idx-1);
        end
    end
else
    fprintf('No suspicious blocks detected (all blocks have reasonable entropy).\n');
end

% Byte histogram for a chosen block (ask user)
if interactive
    blockIdx_str = inputdlg('Enter block index for histogram (default 10):', 'Block Select', 1, {num2str(min(10, size(mats{1},1)))});
    if ~isempty(blockIdx_str)
        blockIdx = str2double(blockIdx_str{1});
    else
        blockIdx = min(10, size(mats{1},1));
    end
else
    blockIdx = min(10, size(mats{1},1));
end

if isnan(blockIdx) || blockIdx < 1 || blockIdx > size(mats{1},1)
    blockIdx = min(10, size(mats{1},1));
end

fprintf('\nHistogram for block %d:\n', blockIdx);
figure('Name',sprintf('Byte histogram block %d', blockIdx),'NumberTitle','off');
histogram(mats{1}(blockIdx,:), 0:255);
xlabel('Byte value (0-255)');
ylabel('Count');
title(sprintf('Byte frequency for block %d (file 1)', blockIdx));

% If a second file was provided, compute differences
if nFiles == 2
    fprintf('\n========================================\n');
    fprintf('FILE COMPARISON\n');
    fprintf('========================================\n');
    minlen = min(numel(dumps{1}), numel(dumps{2}));
    diffs = find(dumps{1}(1:minlen) ~= dumps{2}(1:minlen));
    fprintf('Bytes that differ: %d differences found\n', numel(diffs));
    if numel(diffs) > 0
        fprintf('(showing up to 200 indices)\n');
        disp(diffs(1:min(200,end))');
    end
    
    % Show small heatmap of XOR differences
    xorvals = bitxor(dumps{1}(1:minlen), dumps{2}(1:minlen));
    xormat = reshape_for_rows(xorvals, bytesPerRow);
    figure('Name','XOR heatmap (file1 XOR file2)','NumberTitle','off');
    imagesc(xormat);
    colorbar;
    title('XOR of file1 and file2; nonzero = changed bytes');
    
    % Sector/block diffs summary
    diff_summary = summarize_sector_diffs(diffs);
    disp(diff_summary);
end

% Offer CSV export for the first file (and second if present)
if interactive
    export = questdlg('Export block matrix to CSV for file 1?', 'Export CSV', 'Yes', 'No', 'No');
    if strcmp(export,'Yes')
        outname = fullfile(path, [files{1} '_blocks.csv']);
        csvwrite(outname, mats{1});
        fprintf('Exported CSV: %s\n', outname);
    end
    
    if nFiles == 2
        export2 = questdlg('Export block matrix to CSV for file 2?', 'Export CSV', 'Yes', 'No', 'No');
        if strcmp(export2,'Yes')
            outname2 = fullfile(path, [files{2} '_blocks.csv']);
            csvwrite(outname2, mats{2});
            fprintf('Exported CSV: %s\n', outname2);
        end
    end
end

% Auto-export if csvout specified
if auto_export
    for k = 1:nFiles
        outname = fullfile(csvout, [files{k} '_blocks.csv']);
        csvwrite(outname, mats{k});
        fprintf('Auto-exported CSV: %s\n', outname);
    end
end

% Done
fprintf('\n========================================\n');
fprintf('ANALYSIS COMPLETE\n');
fprintf('========================================\n');
fprintf('Inspect the figures and the CSV if exported.\n');
if return_struct
    varargout{1} = out_struct;
end

% ========================================
% HELPER FUNCTIONS
% ========================================

function uid_info = decode_uid(block0)
% Block 0 format: [UID0 UID1 UID2 UID3 BCC SAK ATQA0 ATQA1 ... ]
uid_bytes = block0(1:4);
bcc = block0(5);
sak = block0(6);
atqa = block0(7:8);

% Calculate BCC (XOR of UID bytes)
bcc_calculated = bitxor(bitxor(bitxor(uid_bytes(1), uid_bytes(2)), uid_bytes(3)), uid_bytes(4));
bcc_valid = (bcc == bcc_calculated);

% Determine UID type
if uid_bytes(1) == hex2dec('08')
    uid_type = 'Random UID (Magic card or randomized)';
elseif uid_bytes(1) == hex2dec('88')
    uid_type = 'Cascade Tag (UID continues, 7-byte UID)';
else
    uid_type = '4-byte UID (Single size)';
end

% Manufacturer lookup (first byte)
manufacturers = containers.Map('KeyType', 'uint32', 'ValueType', 'char');
manufacturers(uint32(hex2dec('04'))) = 'NXP Semiconductors';
manufacturers(uint32(hex2dec('02'))) = 'ST Microelectronics';
manufacturers(uint32(hex2dec('05'))) = 'Infineon Technologies';
manufacturers(uint32(hex2dec('08'))) = 'Various/Magic Card';
manufacturers(uint32(hex2dec('09'))) = 'Fudan Microelectronics';
manufacturers(uint32(hex2dec('0A'))) = 'NXP/Shanghai Fudan';
manufacturers(uint32(hex2dec('88'))) = 'Cascade (multi-byte UID)';

if isKey(manufacturers, uint32(uid_bytes(1)))
    manufacturer = manufacturers(uint32(uid_bytes(1)));
else
    manufacturer = sprintf('Unknown (0x%02X)', uid_bytes(1));
end

uid_info = struct();
uid_info.uid_hex = sprintf('%02X%02X%02X%02X', uid_bytes);
uid_info.uid_bytes = uid_bytes;
uid_info.bcc = bcc;
uid_info.bcc_calculated = bcc_calculated;
uid_info.bcc_valid = bcc_valid;
uid_info.sak = sak;
uid_info.atqa = atqa;
uid_info.uid_type = uid_type;
uid_info.manufacturer = manufacturer;
end

function ascii_strings = extract_ascii_strings(dump)
ascii_strings = struct('strings', {}, 'locations', {});
min_length = 4; % Minimum string length to consider

current_str = '';
start_idx = 0;

for i = 1:numel(dump)
    byte = dump(i);
    % Consider printable ASCII (32-126) and common extended chars
    if (byte >= 32 && byte <= 126) || byte == 10 || byte == 13
        if isempty(current_str)
            start_idx = i;
        end
        current_str = [current_str char(byte)];
    else
        if length(current_str) >= min_length
            % Found a string
            idx = length(ascii_strings) + 1;
            ascii_strings(idx).strings = strtrim(current_str);
            ascii_strings(idx).locations = [start_idx, i-1];
            ascii_strings(idx).sector = floor((start_idx-1)/64);
            ascii_strings(idx).block = floor((start_idx-1)/16);
        end
        current_str = '';
    end
end

% Catch final string if exists
if length(current_str) >= min_length
    idx = length(ascii_strings) + 1;
    ascii_strings(idx).strings = strtrim(current_str);
    ascii_strings(idx).locations = [start_idx, numel(dump)];
    ascii_strings(idx).sector = floor((start_idx-1)/64);
    ascii_strings(idx).block = floor((start_idx-1)/16);
end
end

function value_blocks = detect_value_blocks(sectors)
value_blocks = struct('sector', {}, 'block', {}, 'value', {}, 'addr', {}, 'valid', {});

for s = 1:numel(sectors)
    for b = 1:3 % Only data blocks
        blk = sectors(s).blockData(b,:);
        
        % Value block format:
        % Bytes 0-3: Value (LSB first)
        % Bytes 4-7: ~Value (inverted)
        % Bytes 8-11: Value (repeated)
        % Byte 12: Address
        % Byte 13: ~Address
        % Byte 14: Address (repeated)
        % Byte 15: ~Address (repeated)
        
        value1 = typecast(uint8(blk(1:4)), 'int32');
        value2_inv = typecast(uint8(blk(5:8)), 'int32');
        value3 = typecast(uint8(blk(9:12)), 'int32');
        
        addr1 = blk(13);
        addr2_inv = blk(14);
        addr3 = blk(15);
        addr4_inv = blk(16);
        
        % Check if it matches value block format
        value2 = bitcmp(value2_inv, 'int32');
        addr2 = bitcmp(addr2_inv, 'uint8');
        addr4 = bitcmp(addr4_inv, 'uint8');
        
        is_valid = (value1 == value2) && (value1 == value3) && ...
                   (addr1 == addr2) && (addr1 == addr3) && (addr1 == addr4);
        
        if is_valid
            idx = length(value_blocks) + 1;
            value_blocks(idx).sector = sectors(s).sector;
            value_blocks(idx).block = sectors(s).sector * 4 + (b-1);
            value_blocks(idx).value = value1;
            value_blocks(idx).addr = addr1;
            value_blocks(idx).valid = true;
        end
    end
end
end

function [is_valid, errors] = validate_access_bits(access_bytes)
b6 = access_bytes(1);
b7 = access_bytes(2);
b8 = access_bytes(3);

errors = {};
is_valid = true;

% Extract C1, C2, C3 and their inverses
c1_low = bitand(b7, 15);
c1_inv_low = bitand(b6, 15);
c2_high = bitshift(bitand(b8, 15), 0);
c2_inv_high = bitshift(bitand(b6, 240), -4);
c3_high = bitshift(bitand(b8, 240), -4);
c3_inv_low = bitshift(bitand(b7, 240), -4);

% Check inversions
if bitxor(c1_low, c1_inv_low) ~= 15
    errors{end+1} = 'C1 bits not properly inverted';
    is_valid = false;
end

if bitxor(c2_high, c2_inv_high) ~= 15
    errors{end+1} = 'C2 bits not properly inverted';
    is_valid = false;
end

if bitxor(c3_high, c3_inv_low) ~= 15
    errors{end+1} = 'C3 bits not properly inverted';
    is_valid = false;
end
end

function card_type = detect_card_type(dump)
dump_size = numel(dump);
if dump_size == 1024
    card_type = 'MIFARE Classic 1K';
elseif dump_size == 4096
    card_type = 'MIFARE Classic 4K';
else
    card_type = 'MIFARE DESFire';
end
end

function apps = parse_desfire(dump)
apps = [];
fprintf('DESFire parsing not implemented.\n');
end

function display_desfire(apps)
fprintf('DESFire display not implemented.\n');
end

function data = read_dump_guess_format(fname)
% Try to detect if the file is binary or ASCII hex (imhex)
[~,~,ext] = fileparts(fname);
txtExts = {'.txt','.imhex','.hex','.dump'};
if any(strcmpi(ext, txtExts))
    s = fileread(fname);
    data = parse_imhex_like(s);
else
    % If extension unknown, peek first bytes
    fid = fopen(fname,'rb');
    peek = fread(fid, 256, 'uint8');
    fclose(fid);
    % Heuristic: if many bytes are non-printable, treat as binary
    if sum(peek < 32)/numel(peek) > 0.5
        % binary
        fid = fopen(fname,'rb');
        data = fread(fid, Inf, 'uint8');
        fclose(fid);
    else
        % text -> parse
        s = fileread(fname);
        data = parse_imhex_like(s);
    end
end
end

function data = parse_imhex_like(s)
% Parse lines containing hex bytes
data = [];
s = strrep(s, sprintf('\r\n'), sprintf('\n'));
lines = strsplit(s, '\n');
for i=1:numel(lines)
    L = strtrim(lines{i});
    if isempty(L), continue; end
    L = regexprep(L, '^\s*0x?[0-9A-Fa-f]+[:)]?\s*', '');
    tokens = regexp(L, '([0-9A-Fa-f]{2})', 'match');
    if ~isempty(tokens)
        bytes = uint8(hex2dec(tokens));
        data = [data; bytes(:)];
    end
end
if isempty(data)
    error('No hex bytes found in file. Make sure it is imhex-like or raw .bin.');
end
end

function mat = reshape_for_rows(data, bytesPerRow)
nrows = ceil(numel(data)/bytesPerRow);
padded = [data; zeros(nrows * bytesPerRow - numel(data), 1, 'uint8')];
mat = reshape(padded, bytesPerRow, nrows)';
end

function preview_ascii(mat, nrows)
nrows = min(nrows, size(mat,1));
for r = 1:nrows
    rowBytes = mat(r,:);
    asciiStr = char(rowBytes);
    asciiStr(asciiStr < 32 | asciiStr > 126) = '.';
    fprintf('%04d: %s\n', r-1, asciiStr);
end
end

function H = block_entropy(block)
% Shannon entropy for a block of uint8
probs = histcounts(block, 0:256) / numel(block);
probs = probs(probs > 0);
if isempty(probs)
    H = 0;
else
    H = -sum(probs .* log2(probs));
end
end

function [keys, access_triples, gp_bytes, sectors] = extract_mifare_keys(dump, nSectors, card_size)
bytesPerSector = 64;
keys = cell(nSectors, 2);
access_triples = cell(nSectors, 1);
gp_bytes = zeros(nSectors, 1, 'uint8');
sectors = struct([]);

for s = 0:nSectors-1
    trailer_start = s * bytesPerSector + 48;
    keyA_bytes = dump(trailer_start + 1 : trailer_start + 6);
    access_bytes = dump(trailer_start + 7 : trailer_start + 9);
    gp_byte = dump(trailer_start + 10);
    keyB_bytes = dump(trailer_start + 11 : trailer_start + 16);
    
    keyA_hex = sprintf('%02X%02X%02X%02X%02X%02X', keyA_bytes);
    keyB_hex = sprintf('%02X%02X%02X%02X%02X%02X', keyB_bytes);
    
    h1 = sprintf('%02X', access_bytes(1));
    h2 = sprintf('%02X', access_bytes(2));
    h3 = sprintf('%02X', access_bytes(3));
    
    keys{s+1, 1} = keyA_hex;
    keys{s+1, 2} = keyB_hex;
    access_triples{s+1} = {h1, h2, h3};
    gp_bytes(s+1) = gp_byte;
    
    % Per-sector struct
    blkBase = s * 4;
    blockData = zeros(4,16,'uint8');
    for b = 0:3
        idx = (blkBase + b)*16 + (1:16);
        blockData(b+1,:) = dump(idx);
    end
    
    suspicious = false(4,1);
    for b = 1:4
        blk = blockData(b,:);
        suspicious(b) = all(blk==0) | all(blk==255);
    end
    
    Cbits = decode_access_bytes(access_bytes);
    perms = cell(4,1);
    perms_detail = struct();
    
    for b = 1:3
        ci = Cbits(b,1);
        cj = Cbits(b,2);
        ck = Cbits(b,3);
        perms{b} = interpret_c_bits(ci, cj, ck, true);
        perms_detail.(['block' num2str(b-1)]) = compute_data_perms_detail(ci, cj, ck);
    end
    
    ci = Cbits(4,1);
    cj = Cbits(4,2);
    ck = Cbits(4,3);
    perms{4} = interpret_c_bits(ci, cj, ck, false);
    perms_detail.trailer = compute_trailer_perms_detail(ci, cj, ck);
    
    [access_valid, access_errors] = validate_access_bits(access_bytes);
    
    sectors(s+1).sector = s;
    sectors(s+1).blockData = blockData;
    sectors(s+1).trailer = blockData(4,:);
    sectors(s+1).KeyA = keyA_bytes;
    sectors(s+1).Access = access_bytes;
    sectors(s+1).GP = gp_byte;
    sectors(s+1).KeyB = keyB_bytes;
    sectors(s+1).Cbits = Cbits;
    sectors(s+1).permissions = perms;
    sectors(s+1).perms_detail = perms_detail;
    sectors(s+1).suspiciousBlocks = suspicious;
    sectors(s+1).accessValid = access_valid;
    sectors(s+1).accessErrors = access_errors;
    
    if s == 0
        uid = sprintf('%02X%02X%02X%02X', blockData(1,1:4));
        sectors(s+1).UID = uid;
    end
end
end

function Cbits = decode_access_bytes(access_bytes)
% Decode access bytes to extract C1, C2, C3 bits for each of 4 blocks
b6 = access_bytes(1);
b7 = access_bytes(2);
b8 = access_bytes(3);

% Extract C1 bits (for blocks 0-3)
C1_bits = bitget(b7, [1 2 3 4]);

% Extract C2 bits (for blocks 0-3)
C2_bits = bitget(b8, [5 6 7 8]);

% Extract C3 bits (for blocks 0-3)
C3_bits = bitget(b8, [1 2 3 4]);

% Build output matrix [4 blocks x 3 bits]
Cbits = [C1_bits' C2_bits' C3_bits'];
end

function perm_str = interpret_c_bits(c1, c2, c3, is_data_block)
if is_data_block
    lookup = {
        'R:AB W:AB I:AB D:AB';
        'R:AB W:-- I:-- D:--';
        'R:AB W:-- I:-- D:--';
        'R:AB W:B  I:B  D:--';
        'R:AB W:AB I:-- D:--';
        'R:B  W:B  I:-- D:--';
        'R:AB W:B  I:-- D:--';
        'R:-- W:-- I:-- D:--'
    };
else
    lookup = {
        'KeyA:W[A] AC:W[A] KeyB:W[A]';
        'KeyA:W[A] AC:R[A] KeyB:W[A]';
        'KeyA:-- AC:R[A] KeyB:--';
        'KeyA:-- AC:R[AB] KeyB:--';
        'KeyA:W[A] AC:W[AB] KeyB:W[A]';
        'KeyA:-- AC:W[AB] KeyB:--';
        'KeyA:-- AC:W[B] KeyB:--';
        'KeyA:-- AC:W[AB] KeyB:--'
    };
end

idx = c1 * 4 + c2 * 2 + c3 + 1;
if idx > 8, idx = 8; end
perm_str = lookup{idx};
end

function perms = compute_data_perms_detail(c1, c2, c3)
perms = struct();
idx = c1 * 4 + c2 * 2 + c3;

switch idx
    case 0
        perms.read = 'A|B'; perms.write = 'A|B'; perms.increment = 'A|B'; perms.decrement = 'A|B';
    case 1
        perms.read = 'A|B'; perms.write = '--'; perms.increment = '--'; perms.decrement = '--';
    case 2
        perms.read = 'A|B'; perms.write = '--'; perms.increment = '--'; perms.decrement = '--';
    case 3
        perms.read = 'A|B'; perms.write = 'B'; perms.increment = 'B'; perms.decrement = '--';
    case 4
        perms.read = 'A|B'; perms.write = 'A|B'; perms.increment = '--'; perms.decrement = '--';
    case 5
        perms.read = 'B'; perms.write = 'B'; perms.increment = '--'; perms.decrement = '--';
    case 6
        perms.read = 'A|B'; perms.write = 'B'; perms.increment = '--'; perms.decrement = '--';
    case 7
        perms.read = '--'; perms.write = '--'; perms.increment = '--'; perms.decrement = '--';
end
end

function perms = compute_trailer_perms_detail(c1, c2, c3)
perms = struct();
idx = c1 * 4 + c2 * 2 + c3;

switch idx
    case 0
        perms.keyA_write = 'A'; perms.access_read = '--'; perms.access_write = 'A'; perms.keyB_write = 'A';
    case 1
        perms.keyA_write = 'A'; perms.access_read = 'A'; perms.access_write = 'A'; perms.keyB_write = 'A';
    case 2
        perms.keyA_write = '--'; perms.access_read = 'A'; perms.access_write = '--'; perms.keyB_write = '--';
    case 3
        perms.keyA_write = '--'; perms.access_read = 'A|B'; perms.access_write = '--'; perms.keyB_write = '--';
    case 4
        perms.keyA_write = 'A'; perms.access_read = 'A'; perms.access_write = 'A|B'; perms.keyB_write = 'A';
    case 5
        perms.keyA_write = '--'; perms.access_read = 'A|B'; perms.access_write = 'A|B'; perms.keyB_write = '--';
    case 6
        perms.keyA_write = '--'; perms.access_read = 'A|B'; perms.access_write = 'B'; perms.keyB_write = '--';
    case 7
        perms.keyA_write = '--'; perms.access_read = 'A|B'; perms.access_write = 'A|B'; perms.keyB_write = '--';
end
end

function result = ternary(condition, true_val, false_val)
if condition
    result = true_val;
else
    result = false_val;
end
end

function summary = summarize_sector_diffs(diffs)
summary = 'Difference summary by sector not yet implemented';
end

function display_sectors_detailed(sectors, keys, access_triples, gp_bytes, ascii_strings, value_blocks)
defaults = {'FFFFFFFFFFFF', 'A0A1A2A3A4A5', '000000000000', 'D3F7D3F7D3F7'};

% Display ASCII strings found
if ~isempty(ascii_strings)
    fprintf('\n========================================\n');
    fprintf('EXTRACTED ASCII STRINGS (min 4 chars)\n');
    fprintf('========================================\n');
    for i = 1:numel(ascii_strings)
        fprintf('Sector %2d, Block %2d, Bytes %4d-%4d: "%s"\n', ...
            ascii_strings(i).sector, ...
            ascii_strings(i).block, ...
            ascii_strings(i).locations(1), ...
            ascii_strings(i).locations(2), ...
            ascii_strings(i).strings);
    end
else
    fprintf('\n========================================\n');
    fprintf('EXTRACTED ASCII STRINGS\n');
    fprintf('========================================\n');
    fprintf('No readable ASCII strings found (min 4 characters).\n');
end

% Display value blocks found
if ~isempty(value_blocks)
    fprintf('\n========================================\n');
    fprintf('VALUE BLOCKS DETECTED\n');
    fprintf('========================================\n');
    fprintf('Sector | Block | Value (signed) | Value (unsigned) | Address\n');
    fprintf('-------|-------|----------------|------------------|--------\n');
    for i = 1:numel(value_blocks)
        fprintf('  %2d   |  %2d   | %14d | %16u | 0x%02X\n', ...
            value_blocks(i).sector, ...
            value_blocks(i).block, ...
            value_blocks(i).value, ...
            typecast(value_blocks(i).value, 'uint32'), ...
            value_blocks(i).addr);
    end
else
    fprintf('\n========================================\n');
    fprintf('VALUE BLOCKS DETECTED\n');
    fprintf('========================================\n');
    fprintf('No value blocks detected.\n');
end

fprintf('\n========================================\n');
fprintf('DETAILED SECTOR-BY-SECTOR ANALYSIS\n');
fprintf('========================================\n');

for s = 1:numel(sectors)
    sector = sectors(s);
    fprintf('\n+--------------------------------------+\n');
    fprintf('| SECTOR %02d                           |\n', sector.sector);
    fprintf('+--------------------------------------+\n');
    
    % Display UID for sector 0
    if sector.sector == 0 && isfield(sector, 'UID')
        fprintf('  UID: %s\n', sector.UID);
        fprintf('\n');
    end
    
    % Display data blocks (0-2)
    for b = 0:2
        blk = sector.blockData(b+1,:);
        abs_block = sector.sector * 4 + b;
        
        % Check if suspicious
        is_suspicious = sector.suspiciousBlocks(b+1);
        susp_flag = '';
        if all(blk == 0)
            susp_flag = ' [!SUSPICIOUS: All 0x00]';
        elseif all(blk == 255)
            susp_flag = ' [!SUSPICIOUS: All 0xFF]';
        end
        
        % Check if value block
        value_flag = '';
        for v = 1:numel(value_blocks)
            if value_blocks(v).block == abs_block
                value_flag = sprintf(' [VALUE BLOCK: %d (0x%08X)]', ...
                    value_blocks(v).value, ...
                    typecast(value_blocks(v).value, 'uint32'));
                break;
            end
        end
        
        fprintf('  Block %d [Data]%s%s:\n', abs_block, susp_flag, value_flag);
        fprintf('    Bytes: ');
        fprintf('%02X ', blk);
        fprintf('\n');
        
        % Show ASCII representation if readable
        ascii_repr = char(blk);
        ascii_repr(blk < 32 | blk > 126) = '.';
        fprintf('    ASCII: %s\n', ascii_repr);
        
        fprintf('    Permissions: %s\n', sector.permissions{b+1});
        fprintf('\n');
    end
    
    % Display trailer block (3)
    abs_block = sector.sector * 4 + 3;
    fprintf('  Block %d [Trailer]:\n', abs_block);
    
    % KeyA
    keyA_hex = keys{s, 1};
    flagA = any(strcmpi(keyA_hex, defaults));
    flag_strA = ternary(flagA, ' [!WEAK KEY]', '');
    fprintf('    KeyA:    %s%s\n', keyA_hex, flag_strA);
    
    % Access bytes (C-bits)
    b6 = uint8(hex2dec(access_triples{s}{1}));
    b7 = uint8(hex2dec(access_triples{s}{2}));
    b8 = uint8(hex2dec(access_triples{s}{3}));
    fprintf('    C-bits:  %s %s %s (hex)\n', access_triples{s}{1}, access_triples{s}{2}, access_triples{s}{3});
    fprintf('             %s %s %s (binary)\n', dec2bin(b6,8), dec2bin(b7,8), dec2bin(b8,8));
    
    % Access bits validation
    if ~sector.accessValid
        fprintf('             [!WARNING: Access bits validation FAILED]\n');
        for e = 1:numel(sector.accessErrors)
            fprintf('             Error: %s\n', sector.accessErrors{e});
        end
    else
        fprintf('             [Access bits valid]\n');
    end
    
    % GP byte
    fprintf('    GP:      %02X\n', gp_bytes(s));
    
    % KeyB
    keyB_hex = keys{s, 2};
    flagB = any(strcmpi(keyB_hex, defaults));
    flag_strB = ternary(flagB, ' [!WEAK KEY]', '');
    fprintf('    KeyB:    %s%s\n', keyB_hex, flag_strB);
    
    % Detailed C-bits decoding
    fprintf('\n    Decoded C-bits per block:\n');
    for b = 0:3
        ci = sector.Cbits(b+1, 1);
        cj = sector.Cbits(b+1, 2);
        ck = sector.Cbits(b+1, 3);
        fprintf('      Block %d: (C1=%d, C2=%d, C3=%d)\n', b, ci, cj, ck);
    end
    
    % Permissions interpretation
    fprintf('\n    Permissions interpretation (per MIFARE Classic rules):\n');
    for b = 0:3
        fprintf('      Block %d: %s\n', b, sector.permissions{b+1});
    end
    fprintf('\n');
end

% Summary of weak keys
fprintf('\n========================================\n');
fprintf('SECURITY SUMMARY\n');
fprintf('========================================\n');
weak_count = 0;
invalid_access_count = 0;
for s = 1:numel(sectors)
    keyA_hex = keys{s, 1};
    keyB_hex = keys{s, 2};
    flagA = any(strcmpi(keyA_hex, defaults));
    flagB = any(strcmpi(keyB_hex, defaults));
    if flagA || flagB
        weak_count = weak_count + 1;
    end
    if ~sectors(s).accessValid
        invalid_access_count = invalid_access_count + 1;
    end
end
fprintf('Sectors with weak keys: %d / %d\n', weak_count, numel(sectors));
fprintf('Sectors with invalid access bits: %d / %d\n', invalid_access_count, numel(sectors));

% Suspicious blocks summary
fprintf('\nSuspicious blocks (all 0x00 or 0xFF):\n');
found_suspicious = false;
for s = 1:numel(sectors)
    sb = find(sectors(s).suspiciousBlocks(1:3)) - 1;
    if ~isempty(sb)
        found_suspicious = true;
        fprintf('  Sector %2d: blocks ', s-1);
        for b = sb(:)'
            abs_block = sectors(s).sector * 4 + b;
            if all(sectors(s).blockData(b+1,:) == 0)
                fprintf('%d(0x00) ', abs_block);
            else
                fprintf('%d(0xFF) ', abs_block);
            end
        end
        fprintf('\n');
    end
end
if ~found_suspicious
    fprintf('  None detected.\n');
end
fprintf('\n');
end

end