import sys
from pathlib import Path
import numpy as np
sys.path.insert(0, "artifacts/evidence/offline-cic-2026-10-29")
from cic_offline_eval import FEATURE_NAMES, build
X,y,times,srcs,_=build(sys.argv[1])
names=list(FEATURE_NAMES)
ssh_i=names.index("ssh_flows_60")
fam=np.array(["ssh" if (yy and X[i,ssh_i]>0) else ("ftp" if yy else "benign") for i,yy in enumerate(y)])
from river import forest
def arf_train_test(tr_mask, te_mask, n_models=10, oversample=1):
    arf=forest.ARFClassifier(n_models=n_models, seed=0)
    idx=np.where(tr_mask)[0]
    # optional oversampling of the minority attack class
    atk_idx=idx[y[idx]==1]
    stream=list(idx)+list(np.repeat(atk_idx, oversample-1)) if oversample>1 else list(idx)
    np.random.RandomState(0).shuffle(stream)
    for i in stream:
        arf.learn_one(dict(zip(names,map(float,X[i]))), int(y[i]))
    te=np.where(te_mask)[0]
    preds=np.array([int(arf.predict_one(dict(zip(names,map(float,X[j])))) or 0) for j in te])
    yt=y[te]
    tp=int(((preds==1)&(yt==1)).sum()); fn=int(((preds==0)&(yt==1)).sum())
    return {"recall":round(tp/(tp+fn),3) if tp+fn else None, "n_attack_pred":int((preds==1).sum()), "n_train_attack":int(y[idx].sum())}
benign=fam=="benign"
print("ARF frozen FTP->SSH, 10 models:", arf_train_test(benign|(fam=="ftp"), fam=="ssh"))
print("ARF frozen FTP->SSH, 30 models:", arf_train_test(benign|(fam=="ftp"), fam=="ssh", n_models=30))
print("ARF frozen FTP->SSH, 10 models, 20x oversample attack:", arf_train_test(benign|(fam=="ftp"), fam=="ssh", oversample=20))
print("RF frozen FTP->SSH (reference): see audit = 0.99")
