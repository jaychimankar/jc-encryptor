/**
 * CipherVault Studio - Cryptanalysis & Entropy Analytics Engine
 */

const CryptoAnalyzer = (function () {
    'use strict';

    // Standard English Letter Frequencies (%)
    const ENGLISH_FREQ = {
        'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
        'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
        'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
        'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
        'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
        'Z': 0.074
    };

    /**
     * Calculates Shannon Entropy H(X) = - sum( p(x) * log2(p(x)) )
     */
    function calculateShannonEntropy(str) {
        if (!str || str.length === 0) return { entropy: 0, totalBits: 0 };

        const freq = {};
        for (let char of str) {
            freq[char] = (freq[char] || 0) + 1;
        }

        let entropy = 0;
        const len = str.length;
        for (let char in freq) {
            const p = freq[char] / len;
            entropy -= p * Math.log2(p);
        }

        return {
            entropy: entropy.toFixed(2), // bits per symbol
            totalBits: (entropy * len).toFixed(1)
        };
    }

    /**
     * Calculates letter frequency distribution & Index of Coincidence (IoC)
     */
    function analyzeFrequency(str) {
        const letters = str.toUpperCase().replace(/[^A-Z]/g, '');
        const N = letters.length;
        const counts = {};
        for (let char of 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') counts[char] = 0;

        for (let char of letters) {
            counts[char]++;
        }

        // Index of Coincidence: sum( f_i * (f_i - 1) ) / ( N * (N - 1) )
        let iocSum = 0;
        for (let char in counts) {
            const f = counts[char];
            iocSum += f * (f - 1);
        }

        const ioc = N > 1 ? (iocSum / (N * (N - 1))) : 0;

        // Percentage distribution
        const frequencies = [];
        for (let char of 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
            const pct = N > 0 ? ((counts[char] / N) * 100).toFixed(1) : 0;
            frequencies.push({ letter: char, count: counts[char], percent: parseFloat(pct) });
        }

        return {
            totalLetters: N,
            ioc: ioc.toFixed(4),
            frequencies: frequencies
        };
    }

    /**
     * Evaluates password complexity, entropy score, and estimated crack time
     */
    function evaluatePassword(password) {
        if (!password) {
            return {
                entropy: 0,
                grade: 'Empty',
                crackTimeStr: 'Instant',
                classes: { lower: 0, upper: 0, digits: 0, symbols: 0 }
            };
        }

        const lowerMatch = password.match(/[a-z]/g) || [];
        const upperMatch = password.match(/[A-Z]/g) || [];
        const digitMatch = password.match(/[0-9]/g) || [];
        const symbolMatch = password.match(/[^a-zA-Z0-9]/g) || [];

        let charsetSize = 0;
        if (lowerMatch.length > 0) charsetSize += 26;
        if (upperMatch.length > 0) charsetSize += 26;
        if (digitMatch.length > 0) charsetSize += 10;
        if (symbolMatch.length > 0) charsetSize += 33;

        if (charsetSize === 0) charsetSize = 256;

        // Total combinations = charsetSize ^ length
        const totalEntropyBits = password.length * Math.log2(charsetSize);

        // Brute-force calculation (assuming 10 billion guesses/sec)
        const guessesPerSec = 10000000000;
        const totalCombinations = Math.pow(charsetSize, password.length);
        const seconds = totalCombinations / guessesPerSec;

        let crackTimeStr = '';
        if (seconds < 1) crackTimeStr = 'Instant (< 1 sec)';
        else if (seconds < 60) crackTimeStr = `${Math.round(seconds)} seconds`;
        else if (seconds < 3600) crackTimeStr = `${Math.round(seconds / 60)} minutes`;
        else if (seconds < 86400) crackTimeStr = `${Math.round(seconds / 3600)} hours`;
        else if (seconds < 31536000) crackTimeStr = `${Math.round(seconds / 86400)} days`;
        else if (seconds < 3153600000) crackTimeStr = `${Math.round(seconds / 31536000)} years`;
        else crackTimeStr = `${(seconds / 31536000).toExponential(2)} years (Unbreakable)`;

        let grade = 'Very Weak';
        let gradeClass = 'rose';
        if (totalEntropyBits >= 80) { grade = 'Extremely Strong'; gradeClass = 'emerald'; }
        else if (totalEntropyBits >= 60) { grade = 'Strong'; gradeClass = 'cyan'; }
        else if (totalEntropyBits >= 40) { grade = 'Moderate'; gradeClass = 'amber'; }

        return {
            entropyBits: totalEntropyBits.toFixed(1),
            grade: grade,
            gradeClass: gradeClass,
            crackTimeStr: crackTimeStr,
            classes: {
                lower: lowerMatch.length,
                upper: upperMatch.length,
                digits: digitMatch.length,
                symbols: symbolMatch.length
            }
        };
    }

    /**
     * Auto-Cracks Caesar shift ciphertext using Chi-Square goodness-of-fit against English frequencies
     */
    function autoCrackCaesar(ciphertext) {
        let bestShift = 0;
        let lowestChiSq = Infinity;
        let bestPlaintext = '';

        for (let shift = 0; shift < 26; shift++) {
            const candidate = CryptoEngine.caesarCipher(ciphertext, shift, true);
            const analysis = analyzeFrequency(candidate);

            let chiSq = 0;
            if (analysis.totalLetters > 0) {
                for (let item of analysis.frequencies) {
                    const expectedCount = (ENGLISH_FREQ[item.letter] / 100) * analysis.totalLetters;
                    const observedCount = item.count;
                    if (expectedCount > 0) {
                        chiSq += Math.pow(observedCount - expectedCount, 2) / expectedCount;
                    }
                }
            }

            if (chiSq < lowestChiSq) {
                lowestChiSq = chiSq;
                bestShift = shift;
                bestPlaintext = candidate;
            }
        }

        return {
            shift: bestShift,
            chiSquareScore: lowestChiSq.toFixed(2),
            plaintext: bestPlaintext
        };
    }

    /**
     * Renders interactive Frequency Histogram in HTML Container
     */
    function renderHistogram(container, frequencies) {
        if (!container) return;
        container.innerHTML = '';

        const maxPercent = Math.max(...frequencies.map(f => f.percent), 12.7);

        frequencies.forEach(item => {
            const wrap = document.createElement('div');
            wrap.className = 'chart-bar-wrap';
            wrap.title = `${item.letter}: ${item.count} (${item.percent}%)`;

            const barHeightPct = (item.percent / maxPercent) * 100;

            const bar = document.createElement('div');
            bar.className = 'chart-bar';
            bar.style.height = `${Math.max(barHeightPct, 2)}%`;

            const label = document.createElement('div');
            label.className = 'chart-label';
            label.textContent = item.letter;

            wrap.appendChild(bar);
            wrap.appendChild(label);
            container.appendChild(wrap);
        });
    }

    return {
        calculateShannonEntropy,
        analyzeFrequency,
        evaluatePassword,
        autoCrackCaesar,
        renderHistogram
    };
})();
