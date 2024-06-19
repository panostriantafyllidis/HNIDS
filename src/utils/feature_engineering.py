import numpy as np
from sklearn.decomposition import KernelPCA
from sklearn.feature_selection import mutual_info_classif
from skfeature.function.information_theoretical_based import FCBF
from skopt import BayesSearchCV


# Feature extraction using KPCA
def extract_features_kpca(X, n_components=10):
    kpca = KernelPCA(n_components=n_components, kernel="rbf", gamma=15)
    X_kpca = kpca.fit_transform(X)
    return X_kpca


# Feature selection using Information Gain and FCBF
def select_features_ig_fcbf(X, y):
    # Information Gain
    ig = mutual_info_classif(X, y)
    ig_sorted_indices = np.argsort(ig)[::-1]

    # Fast Correlation-Based Filter
    fcbf_indices = FCBF.fcbf(X, y)

    # Combine IG and FCBF results
    combined_indices = np.intersect1d(ig_sorted_indices, fcbf_indices)
    X_selected = X[:, combined_indices]
    return X_selected


# Hyper-parameter optimization using Bayesian Optimization with Gaussian Processes
def optimize_hyperparameters(estimator, param_space, X, y):
    opt = BayesSearchCV(
        estimator,
        param_space,
        n_iter=30,
        cv=3,
        scoring="accuracy",
        n_jobs=-1,
        random_state=42,
    )
    opt.fit(X, y)
    return opt.best_estimator_
