#!/bin/bash
#
# Author: Hein Htet Zaw
# Script: recover_files.sh
# Purpose: Recover files (.txt, .docx, .pptx, .pdf, .jpg, .png, .mov)
#          from a given .pcap file automatically
#

# Input pcap file
PCAP="FileDownloadTraffic.pcap"
OUTDIR="RecoveredFiles"

# Create output directory
mkdir -p "$OUTDIR/http"
mkdir -p "$OUTDIR/tcp"

echo "[*] Recovering files from $PCAP ..."
echo "-----------------------------------"

######################################
# 1. Extract via HTTP (simplest way) #
######################################
echo "[*] Exporting HTTP objects..."
tshark -r "$PCAP" --export-objects "http,$OUTDIR/http" 2>/dev/null

######################################
# 2. Extract raw TCP streams         #
######################################
echo "[*] Scanning TCP streams for file signatures..."

# Count TCP streams
STREAMS=$(tshark -r "$PCAP" -T fields -e tcp.stream 2>/dev/null | sort -n | uniq)

for stream in $STREAMS; do
    OUTHEX="$OUTDIR/tcp/stream_$stream.hex"
    OUTBIN="$OUTDIR/tcp/stream_$stream.bin"

    # Dump raw TCP stream in hex
    tshark -r "$PCAP" -q -z "follow,tcp,raw,$stream" 2>/dev/null > "$OUTHEX"

    # Convert hex to binary
    xxd -r -p "$OUTHEX" "$OUTBIN"

    # Check file signature
    if grep -q "PK\x03\x04" "$OUTBIN"; then
        mv "$OUTBIN" "$OUTDIR/tcp/file_${stream}.docx"
        echo "  [+] Found DOCX in stream $stream"
    elif grep -q "%PDF" "$OUTBIN"; then
        mv "$OUTBIN" "$OUTDIR/tcp/file_${stream}.pdf"
        echo "  [+] Found PDF in stream $stream"
    elif grep -q "ftyp" "$OUTBIN"; then
        mv "$OUTBIN" "$OUTDIR/tcp/file_${stream}.mov"
        echo "  [+] Found MOV/MP4 in stream $stream"
    elif grep -q "\xFF\xD8" "$OUTBIN"; then
        mv "$OUTBIN" "$OUTDIR/tcp/file_${stream}.jpg"
        echo "  [+] Found JPG in stream $stream"
    elif grep -q "PNG" "$OUTBIN"; then
        mv "$OUTBIN" "$OUTDIR/tcp/file_${stream}.png"
        echo "  [+] Found PNG in stream $stream"
    elif file "$OUTBIN" | grep -q "text"; then
        mv "$OUTBIN" "$OUTDIR/tcp/file_${stream}.txt"
        echo "  [+] Found TXT in stream $stream"
    else
        rm "$OUTBIN"   # delete useless binary
    fi

    rm "$OUTHEX"
done

echo "[*] Recovery complete."
echo "Recovered files saved in: $OUTDIR"
