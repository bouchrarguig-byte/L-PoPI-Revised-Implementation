#!/usr/bin/env bash
set -euo pipefail

REPO="$(pwd)"
CAMPAIGN="$HOME/LPOPI_R1_3_MULTIDEVICE"
PY="$HOME/espcheck/bin/python"

DEVICE="${1:-}"

if [[ ! "$DEVICE" =~ ^D[0-5]$ ]]; then
    echo "Usage: $0 D0|D1|D2|D3|D4|D5"
    exit 1
fi

COMMIT=$(git -C "$REPO" rev-parse --short=7 HEAD)

echo "=============================================="
echo " L-PoPI MULTI-DEVICE SRAM-PUF CAMPAIGN"
echo " Device : $DEVICE"
echo " Commit : $COMMIT"
echo "=============================================="

if ! git -C "$REPO" merge-base --is-ancestor 697f8d3 HEAD; then
    echo "ERREUR: la campagne ne dérive pas du commit scientifique 697f8d3."
    exit 1
fi

if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]; then
    echo "ERREUR: le dépôt contient des modifications non committées."
    echo "Committez les modifications avant l'acquisition."
    exit 1
fi

DEST="$CAMPAIGN/$DEVICE"

if [ -d "$DEST/puf_results" ]; then
    echo "ERREUR: des résultats existent déjà pour $DEVICE."
    echo "Aucun fichier ne sera écrasé."
    exit 1
fi

mkdir -p "$DEST"

{
    echo "device=$DEVICE"
    echo "git_commit=$COMMIT"
    echo "date_start=$(date -Iseconds)"
    echo "region=1"
    echo "address=0x3FFF2000"
    echo "region_bytes=256"
    echo "captures=30"
    echo "enrollment=001-020"
    echo "heldout=021-030"
} > "$DEST/metadata.txt"

echo
echo "IMPORTANT:"
echo "1. La carte $DEVICE doit être DEBRANCHEE maintenant."
echo "2. Le bouton RESET ne doit PAS être utilisé."
echo "3. Chaque cycle = déconnexion complète USB."
echo "4. Attendre 10 secondes hors tension."
echo
read -p "Appuyez sur ENTREE lorsque la carte est débranchée..."

cd "$DEST"

"$PY" "$REPO/collect_puf.py" 2>&1 | tee collection.log

if [ -d puf_results ]; then
    sha256sum puf_results/capture_*.txt > SHA256SUMS.txt
    echo "date_end=$(date -Iseconds)" >> metadata.txt

    COUNT=$(find puf_results -name 'capture_*.txt' | wc -l)

    echo
    echo "=============================================="
    echo " DEVICE $DEVICE TERMINE"
    echo " Captures enregistrées : $COUNT / 30"
    echo " Dossier : $DEST"
    echo "=============================================="

    if [ "$COUNT" -ne 30 ]; then
        echo "ATTENTION: campagne incomplète."
        exit 2
    fi
fi
