'use strict';

const config = require('./config');

/**
 * Blend AHP, ML, and anomaly scores into a single risk value.
 *
 * Weights come from config. If the ML sidecar is unavailable the ML weight is
 * redistributed proportionally to AHP + anomaly so the blend still sums to 1
 * — this is the graceful degradation path.
 */
function computeEnsembleRisk({ ahpScore, mlResult, anomalyScore }) {
  const wA = config.ensembleAhpWeight;
  const wM = config.ensembleMlWeight;
  const wN = config.ensembleAnomalyWeight;

  const mlAvailable = !!(mlResult && mlResult.available === true);
  let weights;
  if (mlAvailable) {
    weights = { ahp: wA, ml: wM, anomaly: wN };
  } else {
    const remainder = wA + wN;
    const scale = remainder > 0 ? 1 / remainder : 0;
    weights = { ahp: wA * scale, ml: 0, anomaly: wN * scale };
  }

  const mlScore = mlAvailable ? mlResult.score : 0;
  const blended =
    weights.ahp * ahpScore +
    weights.ml * mlScore +
    weights.anomaly * anomalyScore;

  const clipped = Math.max(0, Math.min(1, blended));

  return {
    ensembleScore: Math.round(clipped * 100) / 100,
    components: {
      ahp: Math.round(ahpScore * 100) / 100,
      ml: Math.round(mlScore * 100) / 100,
      anomaly: Math.round(anomalyScore * 100) / 100,
    },
    weights: {
      ahp: Math.round(weights.ahp * 1000) / 1000,
      ml: Math.round(weights.ml * 1000) / 1000,
      anomaly: Math.round(weights.anomaly * 1000) / 1000,
    },
    mlAvailable,
    mlError: mlAvailable ? null : (mlResult && mlResult.error) || 'unknown',
    mlModelVersion: mlAvailable ? mlResult.modelVersion : null,
    mlExplanation: mlAvailable ? mlResult.explanation : null,
  };
}

module.exports = { computeEnsembleRisk };
