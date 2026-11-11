const GIF = "/assets/img/logo.gif";
const SIZE = 64;

function iconLink() {
  let link = document.querySelector('link[rel="icon"]');
  if (!link) {
    link = document.createElement("link");
    link.rel = "icon";
    document.head.appendChild(link);
  }
  return link;
}

async function decodeFrames() {
  const res = await fetch(GIF);
  const data = await res.arrayBuffer();
  const decoder = new ImageDecoder({ data, type: "image/gif" });
  await decoder.tracks.ready;
  const count = decoder.tracks.selectedTrack.frameCount;
  const canvas = document.createElement("canvas");
  canvas.width = SIZE;
  canvas.height = SIZE;
  const ctx = canvas.getContext("2d");
  const frames = [];
  for (let i = 0; i < count; i += 1) {
    const { image } = await decoder.decode({ frameIndex: i });
    ctx.clearRect(0, 0, SIZE, SIZE);
    ctx.drawImage(image, 0, 0, SIZE, SIZE);
    frames.push({ url: canvas.toDataURL("image/png"), delay: Math.max((image.duration || 100000) / 1000, 40) });
    image.close();
  }
  decoder.close();
  return frames;
}

export async function animateFavicon() {
  const link = iconLink();
  if (!("ImageDecoder" in window)) {
    link.type = "image/gif";
    link.href = GIF;
    return;
  }
  let frames;
  try {
    frames = await decodeFrames();
  } catch {
    link.type = "image/gif";
    link.href = GIF;
    return;
  }
  if (!frames.length) return;
  link.type = "image/png";
  let index = 0;
  let timer = null;
  const tick = () => {
    link.href = frames[index].url;
    const wait = frames[index].delay;
    index = (index + 1) % frames.length;
    timer = setTimeout(tick, wait);
  };
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      clearTimeout(timer);
      timer = null;
    } else if (!timer) {
      tick();
    }
  });
  tick();
}
