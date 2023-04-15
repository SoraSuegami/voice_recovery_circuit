export function countOnes(hexString) {
  // 16進数文字列をバイト配列に変換
  let byteArray = [];
  for (let i = 2; i < hexString.length; i += 2) {
    byteArray.push(parseInt(hexString.substr(i, 2), 16));
  }

  // バイト配列をビット列に変換して1の数を数える
  let ones = 0;
  for (let i = 0; i < byteArray.length; i++) {
    let byte = byteArray[i];
    while (byte !== 0) {
      ones += byte & 1;
      byte >>= 1;
    }
  }

  return ones;
}
