/**
 * K-Means Algorithm Implementation with K-Means++ Initialization,
 * Convergence Tracking, Silhouette Score, and Inertia Calculation.
 */

export class KMeans {
  /**
   * @param {Object} options
   * @param {number} options.k - Number of clusters
   * @param {number} options.maxIterations - Maximum iterations
   * @param {number} options.tolerance - Convergence threshold
   */
  constructor({ k = 3, maxIterations = 50, tolerance = 1e-4 } = {}) {
    this.k = Math.max(1, k);
    this.maxIterations = maxIterations;
    this.tolerance = tolerance;
  }

  /**
   * Euclidean distance between two 2D points
   */
  static distance(p1, p2) {
    const dx = p1.x - p2.x;
    const dy = p1.y - p2.y;
    return Math.sqrt(dx * dx + dy * dy);
  }

  /**
   * Squared Euclidean distance
   */
  static distanceSq(p1, p2) {
    const dx = p1.x - p2.x;
    const dy = p1.y - p2.y;
    return dx * dx + dy * dy;
  }

  /**
   * K-Means++ Smart Initialization
   * Ensures spread-out initial centroids for faster convergence and better local minima.
   */
  initCentroids(points) {
    const centroids = [];
    const n = points.length;
    if (n === 0) return centroids;

    // Pick 1st centroid uniformly at random
    const firstIdx = Math.floor(Math.random() * n);
    centroids.push({ x: points[firstIdx].x, y: points[firstIdx].y });

    // Pick remaining k - 1 centroids with probability proportional to D(x)^2
    for (let c = 1; c < this.k; c++) {
      const distancesSq = new Float64Array(n);
      let sumDistSq = 0;

      for (let i = 0; i < n; i++) {
        let minDistSq = Infinity;
        for (let j = 0; j < centroids.length; j++) {
          const dSq = KMeans.distanceSq(points[i], centroids[j]);
          if (dSq < minDistSq) minDistSq = dSq;
        }
        distancesSq[i] = minDistSq;
        sumDistSq += minDistSq;
      }

      // Sample next centroid
      let randVal = Math.random() * sumDistSq;
      let selectedIdx = 0;
      for (let i = 0; i < n; i++) {
        randVal -= distancesSq[i];
        if (randVal <= 0) {
          selectedIdx = i;
          break;
        }
      }
      centroids.push({ x: points[selectedIdx].x, y: points[selectedIdx].y });
    }

    return centroids;
  }

  /**
   * Fit K-Means on the points
   * @param {Array<{x: number, y: number}>} points
   * @returns {Object} clustering result
   */
  fit(points) {
    if (!points || points.length === 0) {
      return {
        centroids: [],
        assignments: [],
        iterations: 0,
        inertia: 0,
        silhouette: 0,
        history: [],
      };
    }

    const actualK = Math.min(this.k, points.length);
    let centroids = this.initCentroids(points).slice(0, actualK);
    const history = []; // captures centroid states per iteration

    let assignments = new Int32Array(points.length);
    let iterations = 0;
    let converged = false;

    // Save initial state
    history.push(centroids.map((c) => ({ ...c })));

    while (iterations < this.maxIterations && !converged) {
      iterations++;

      // 1. Assignment Step
      for (let i = 0; i < points.length; i++) {
        let minD = Infinity;
        let bestCluster = 0;
        for (let j = 0; j < centroids.length; j++) {
          const d = KMeans.distanceSq(points[i], centroids[j]);
          if (d < minD) {
            minD = d;
            bestCluster = j;
          }
        }
        assignments[i] = bestCluster;
      }

      // 2. Update Step (Compute new centroids as cluster means)
      const sumX = new Float64Array(actualK);
      const sumY = new Float64Array(actualK);
      const counts = new Int32Array(actualK);

      for (let i = 0; i < points.length; i++) {
        const cluster = assignments[i];
        sumX[cluster] += points[i].x;
        sumY[cluster] += points[i].y;
        counts[cluster]++;
      }

      let maxShift = 0;
      const nextCentroids = [];

      for (let j = 0; j < actualK; j++) {
        if (counts[j] > 0) {
          const newX = sumX[j] / counts[j];
          const newY = sumY[j] / counts[j];
          const shift = Math.sqrt(
            Math.pow(newX - centroids[j].x, 2) + Math.pow(newY - centroids[j].y, 2)
          );
          if (shift > maxShift) maxShift = shift;
          nextCentroids.push({ x: newX, y: newY });
        } else {
          // Empty cluster fallback: reinitialize to point farthest from any centroid
          let maxDist = -1;
          let candidate = points[0];
          for (let p of points) {
            let nearestDist = Infinity;
            for (let c of centroids) {
              const d = KMeans.distanceSq(p, c);
              if (d < nearestDist) nearestDist = d;
            }
            if (nearestDist > maxDist) {
              maxDist = nearestDist;
              candidate = p;
            }
          }
          nextCentroids.push({ x: candidate.x, y: candidate.y });
          maxShift = Math.max(maxShift, 1.0);
        }
      }

      centroids = nextCentroids;
      history.push(centroids.map((c) => ({ ...c })));

      if (maxShift < this.tolerance) {
        converged = true;
      }
    }

    // Final assignments
    for (let i = 0; i < points.length; i++) {
      let minD = Infinity;
      let bestCluster = 0;
      for (let j = 0; j < centroids.length; j++) {
        const d = KMeans.distanceSq(points[i], centroids[j]);
        if (d < minD) {
          minD = d;
          bestCluster = j;
        }
      }
      assignments[i] = bestCluster;
    }

    // Calculate Inertia (Within-Cluster Sum of Squares)
    let inertia = 0;
    const clusterStats = centroids.map((c, idx) => ({
      clusterIndex: idx,
      centroid: c,
      count: 0,
      inertia: 0,
      avgDistance: 0,
      stdDev: 0,
    }));

    for (let i = 0; i < points.length; i++) {
      const cluster = assignments[i];
      const dSq = KMeans.distanceSq(points[i], centroids[cluster]);
      inertia += dSq;
      clusterStats[cluster].count++;
      clusterStats[cluster].inertia += dSq;
    }

    // Additional cluster stats
    for (let stat of clusterStats) {
      if (stat.count > 0) {
        stat.avgDistance = Math.sqrt(stat.inertia / stat.count);
        stat.stdDev = stat.avgDistance; // proxy for cluster spread radius
      }
    }

    // Calculate Silhouette Score
    const silhouette = this.calculateSilhouette(points, assignments, actualK);

    return {
      k: actualK,
      centroids,
      assignments: Array.from(assignments),
      iterations,
      converged,
      inertia,
      silhouette,
      clusterStats,
      history,
    };
  }

  /**
   * Silhouette score: measures cohesion vs separation
   * Sample-capped to 300 points for real-time responsiveness.
   */
  calculateSilhouette(points, assignments, k) {
    if (k < 2 || points.length < 2) return 0;

    // Subsample if large to keep 60 FPS performance
    const sampleSize = Math.min(points.length, 250);
    const indices = [];
    const step = points.length / sampleSize;
    for (let i = 0; i < sampleSize; i++) {
      indices.push(Math.floor(i * step));
    }

    let totalScore = 0;
    let validPoints = 0;

    for (let idx of indices) {
      const p = points[idx];
      const ownCluster = assignments[idx];

      // a(i): average distance to points in same cluster
      let intraDistSum = 0;
      let intraCount = 0;

      // b(i): minimum average distance to points in other clusters
      const interDistSums = new Float64Array(k);
      const interCounts = new Int32Array(k);

      for (let j = 0; j < points.length; j++) {
        if (j === idx) continue;
        const other = points[j];
        const otherCluster = assignments[j];
        const dist = KMeans.distance(p, other);

        if (otherCluster === ownCluster) {
          intraDistSum += dist;
          intraCount++;
        } else {
          interDistSums[otherCluster] += dist;
          interCounts[otherCluster]++;
        }
      }

      if (intraCount === 0) continue; // isolated point

      const a = intraDistSum / intraCount;

      let b = Infinity;
      for (let c = 0; c < k; c++) {
        if (c !== ownCluster && interCounts[c] > 0) {
          const avgD = interDistSums[c] / interCounts[c];
          if (avgD < b) b = avgD;
        }
      }

      if (!isFinite(b)) continue;

      const maxAB = Math.max(a, b);
      const s = maxAB > 0 ? (b - a) / maxAB : 0;
      totalScore += s;
      validPoints++;
    }

    return validPoints > 0 ? Number((totalScore / validPoints).toFixed(3)) : 0;
  }
}
