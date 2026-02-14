# """
# Federated Learning Server - Integrated with Stage 1
# Coordinates training across multiple organizations
# """
# import numpy as np
# from flwr.common import ndarrays_to_parameters

# import flwr as fl
# from flwr.server import ServerConfig
# from typing import List, Tuple, Dict
# from flwr.common import Metrics


# def weighted_average(metrics: List[Tuple[int, Metrics]]) -> Metrics:
#     """
#     Aggregate metrics from multiple clients using weighted average.
    
#     Args:
#         metrics: List of (num_examples, metrics_dict) from each client
    
#     Returns:
#         Aggregated metrics dictionary
#     """
#     total_examples = sum([num_examples for num_examples, _ in metrics])
    
#     if total_examples == 0:
#         return {}
    
#     aggregated = {}
    
#     if metrics:
#         metric_keys = metrics[0][1].keys()
        
#         for key in metric_keys:
#             weighted_sum = sum([num_examples * m[key] for num_examples, m in metrics])
#             aggregated[key] = weighted_sum / total_examples
    
#     # Display results
#     print(f"\n{'='*70}")
#     print(f"AGGREGATED METRICS ACROSS ALL ORGANIZATIONS:")
#     print(f"{'='*70}")
#     for key, value in aggregated.items():
#         if 'accuracy' in key.lower():
#             print(f"  {key.upper():20} {value*100:.2f}%")
#         elif 'loss' in key.lower():
#             print(f"  {key.upper():20} {value:.4f}")
#         else:
#             print(f"  {key:20} {value:.2f}")
#     print(f"{'='*70}\n")
    
#     return aggregated

# def get_initial_parameters():
#     # 15 features → 1 output (logistic regression)
#     weights = np.zeros((1, 15), dtype=np.float32)
#     bias = np.zeros((1,), dtype=np.float32)
#     return ndarrays_to_parameters([weights, bias])

# def main():
#     """Start the federated learning server."""
#     print("="*70)
#     print("INTEGRATED FEDERATED LEARNING SERVER")
#     print("="*70)
#     print("Coordinating ransomware detection training")
#     print("Using Stage 1's 15-feature model")
#     print()
#     print("Configuration:")
#     print("  • Server address: 127.0.0.1:8080")
#     print("  • Training rounds: 5")
#     print("  • Min clients: 2")
#     print("  • Strategy: FedAvg (Federated Averaging)")
#     print()
#     print("Waiting for organizations to connect...")
#     print("  → Hospital")
#     print("  → Bank")
#     print("  → University")
#     print("="*70 + "\n")
    
#     # Federated Averaging strategy
# strategy = fl.server.strategy.FedAvg(
#     initial_parameters=get_initial_parameters(),

#         fraction_fit=1.0,  # Use all available clients
#         fraction_evaluate=1.0,
#         min_fit_clients=2,  # Minimum 2 organizations
#         min_evaluate_clients=2,
#         min_available_clients=2,
#         evaluate_metrics_aggregation_fn=weighted_average,
#         fit_metrics_aggregation_fn=weighted_average,
#     )
    
#     # Server configuration
#     config = ServerConfig(num_rounds=5)  # 5 training rounds
    
#     # Start server
#     print("🚀 Starting federated learning server...\n")
    
#     fl.server.start_server(
#         server_address="127.0.0.1:8080",
#         config=config,
#         strategy=strategy,
#     )
    
#     print("\n" + "="*70)
#     print("✅ FEDERATED LEARNING COMPLETE!")
#     print("="*70)
#     print("\nAll organizations have trained collaboratively!")
#     print("Model improved across rounds without sharing data.")
#     print("\nBenefits:")
#     print("  ✅ Privacy preserved (no data sharing)")
#     print("  ✅ Better model (learned from all organizations)")
#     print("  ✅ Faster detection (collective intelligence)")
#     print("="*70)


# if __name__ == "__main__":
#     main()
"""
Federated Learning Server - Integrated with Stage 1
Coordinates training across multiple organizations
"""

import numpy as np
import flwr as fl
from flwr.server import ServerConfig
from flwr.common import Metrics, ndarrays_to_parameters
from typing import List, Tuple


def weighted_average(metrics: List[Tuple[int, Metrics]]) -> Metrics:
    """Aggregate metrics from multiple clients using weighted average."""
    total_examples = sum([num_examples for num_examples, _ in metrics])
    if total_examples == 0:
        return {}

    aggregated = {}
    metric_keys = metrics[0][1].keys()

    for key in metric_keys:
        aggregated[key] = sum(
            [num_examples * m[key] for num_examples, m in metrics]
        ) / total_examples

    print(f"\n{'='*70}")
    print("AGGREGATED METRICS ACROSS ALL ORGANIZATIONS:")
    print(f"{'='*70}")
    for key, value in aggregated.items():
        if "accuracy" in key.lower():
            print(f"  {key.upper():20} {value*100:.2f}%")
        elif "loss" in key.lower():
            print(f"  {key.upper():20} {value:.4f}")
        else:
            print(f"  {key:20} {value:.2f}")
    print(f"{'='*70}\n")

    return aggregated


def get_initial_parameters():
    # Logistic regression: 15 features → 1 output
    weights = np.zeros((1, 15), dtype=np.float32)
    bias = np.zeros((1,), dtype=np.float32)
    return ndarrays_to_parameters([weights, bias])


def main():
    print("=" * 70)
    print("INTEGRATED FEDERATED LEARNING SERVER")
    print("=" * 70)
    print("Coordinating ransomware detection training")
    print("Using Stage 1's 15-feature model\n")

    print("Configuration:")
    print("  • Server address: 127.0.0.1:8080")
    print("  • Training rounds: 5")
    print("  • Min clients: 2")
    print("  • Strategy: FedAvg (Federated Averaging)\n")

    print("Waiting for organizations to connect...")
    print("  → Hospital")
    print("  → Bank")
    print("  → University")
    print("=" * 70 + "\n")

    # 🔥 Correct FedAvg with cold-start model
    strategy = fl.server.strategy.FedAvg(
        initial_parameters=get_initial_parameters(),
        fraction_fit=1.0,
        fraction_evaluate=1.0,
        min_fit_clients=3,
        min_evaluate_clients=3,
        min_available_clients=3,
        evaluate_metrics_aggregation_fn=weighted_average,
        fit_metrics_aggregation_fn=weighted_average,
    )

    config = ServerConfig(num_rounds=5)

    print("🚀 Starting federated learning server...\n")

    fl.server.start_server(
        server_address="127.0.0.1:8080",
        config=config,
        strategy=strategy,
    )

    print("\n" + "=" * 70)
    print("✅ FEDERATED LEARNING COMPLETE!")
    print("=" * 70)


if __name__ == "__main__":
    main()
