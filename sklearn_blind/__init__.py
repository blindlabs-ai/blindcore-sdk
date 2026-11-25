"""Zero-Key Encrypted scikit-learn Estimator Suite over BlindCore PLWE0001.

Two-mode cryptographic contract:
  - Mode 1 (BlindSklearnConnector): Encrypted-at-rest SQL bridge to NumPy plus native
    in-DB ML_LINEAR_SCORE, ML_TREE_SCORE, and ML_ANOMALY_Z pushdown. Supports 100% of
    stock scikit-learn estimators transparently.
  - Mode 2 (BlindOlapSession + Blind* estimators): Zero-knowledge client-key PLWE0001
    compute where the untrusted server holds zero keys, evaluates radix-packed SUM and
    WEIGHTED_SUM strictly over 80 B IND-CPA ciphertexts, and signs NSAU0001 receipts.
    Nonlinear steps (log/exp/softmax, Cholesky/SVD solve, split discovery, RFF cosine
    maps) run locally on the client over decrypted sufficient stats or leaf indicators.
"""

from .clustering import BlindKMeans, BlindNearestCentroid
from .connector import BlindOlapSession, BlindSklearnConnector
from .generative import (
    BlindGaussianNB,
    BlindLinearDiscriminantAnalysis,
    BlindQuadraticDiscriminantAnalysis,
)
from .kernel_anomaly import BlindEllipticEnvelope, BlindRBFSampler, BlindZScoreDetector
from .linear import (
    BlindLasso,
    BlindLinearRegression,
    BlindLinearSVC,
    BlindLogisticRegression,
    BlindRidge,
    BlindRidgeClassifier,
    BlindSGDClassifier,
)
from .naive_bayes import BlindBernoulliNB, BlindComplementNB, BlindMultinomialNB
from .packing import (
    RadixSlotPacker,
    check_weighted_sum_noise,
    choose_signed_packer,
    choose_unsigned_packer,
)
from .preprocessing import (
    BlindCountVectorizer,
    BlindHashingVectorizer,
    BlindMinMaxScaler,
    BlindStandardScaler,
)
from .trees import (
    BlindDecisionTreeClassifier,
    BlindGradientBoostingClassifier,
    BlindRandomForestClassifier,
)

__all__ = [
    "RadixSlotPacker",
    "check_weighted_sum_noise",
    "choose_unsigned_packer",
    "choose_signed_packer",
    "BlindSklearnConnector",
    "BlindOlapSession",
    "BlindMultinomialNB",
    "BlindBernoulliNB",
    "BlindComplementNB",
    "BlindLinearRegression",
    "BlindRidge",
    "BlindLasso",
    "BlindRidgeClassifier",
    "BlindLogisticRegression",
    "BlindSGDClassifier",
    "BlindLinearSVC",
    "BlindGaussianNB",
    "BlindLinearDiscriminantAnalysis",
    "BlindQuadraticDiscriminantAnalysis",
    "BlindDecisionTreeClassifier",
    "BlindRandomForestClassifier",
    "BlindGradientBoostingClassifier",
    "BlindNearestCentroid",
    "BlindKMeans",
    "BlindStandardScaler",
    "BlindMinMaxScaler",
    "BlindCountVectorizer",
    "BlindHashingVectorizer",
    "BlindRBFSampler",
    "BlindZScoreDetector",
    "BlindEllipticEnvelope",
]
