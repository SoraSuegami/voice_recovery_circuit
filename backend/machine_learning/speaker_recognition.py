# 音声入力に対して特徴量を計算する関数を定義する
from .RawNet3.models import RawNet3

from .RawNet3.infererence import extract_speaker_embd
import torch
import numpy as np
import soundfile

def calc_feat_vec(input_wav_path):
    """
    音声入力に対して特徴量を計算する関数

    Parameters
    ----------
    input_wav_path : string
        音声データのファイルパスまたはwavファイルをnumpy.arrayに変換したもの。shapeは(10,48000)。
    """
    # 1. 変数の用意
    # model.ptのパス
    path_pt = "./backend/machine_learning/RawNet3/models/weights/model.pt"

    n_segments = 10
    gpu = False

    # 2. 音声データを読み込む
    torch_model = RawNet3.MainModel(
        encoder_type="ECA",
        nOut=256,
        out_bn=False,
        sinc_stride=10,
        log_sinc=True,
        norm_sinc="mean",
        grad_mult=1)
    torch_model.load_state_dict(torch.load(path_pt, map_location=lambda storage, loc: storage)["model"])
    torch_model.eval()

    audio, sample_rate = soundfile.read(input_wav_path)

    # 3. 音声データを特徴量に変換する
    output = extract_speaker_embd(
            torch_model,
            audio,
            sample_rate,
            n_samples=48000,
            n_segments=n_segments,
            gpu=gpu,
        ).mean(0)
    feat_vec = output

    binary_vec = np.where(feat_vec > 0, 1, 0)

    # 4. 特徴量を返す
    return binary_vec