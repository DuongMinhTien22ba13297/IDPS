# Restore IDPS after removing a local checkout or virtual machine

The repository preserves the application source, Docker build definitions,
configuration templates, default trained models, experiment models and evaluation
reports. It does not preserve a VMware disk or the complete previous lab state.

## Restore the application

1. Clone the repository:

   ```bash
   git clone https://github.com/DuongMinhTien22ba13297/IDPS.git
   cd IDPS
   ```

2. Prepare a Linux host or create a new Ubuntu virtual machine. Install Git,
   Docker Engine and Docker Compose v2. The repository does not install the guest
   operating system or recreate VMware network adapters.
3. Follow the configuration and launch steps in the root [README](../README.md).
   Adapt the external capture interface, management whitelist and Grafana/Loki
   bind addresses to the new host. The checked-in lab address is
   `192.168.226.151`, the external interface defaults to `ens33`, and Compose
   creates a Docker bridge named `br-idps`.
4. Start in monitor-only mode and check service logs before enabling enforcement.
   Default model inference does not require the training CSV files.

The default `models/` bundle belongs to `20260908_botnet_excluded_v1`.
Connection Count v2 models are retained under
`experiments/20260913_connection_count_10s_v2/models/` and are not automatically
selected by the default Compose mounts. Keep each model bundle together with
its encoder and metadata when choosing a different experiment.

## Restore research inputs and historical state

The following items are excluded from Git and cannot be recovered by cloning:

- Raw and processed datasets, including
  `datasets/cic2017_nfs_labeled_57features.csv`.
- Experiment data partitions, including
  `experiments/20260913_connection_count_10s_v2/data/final_test.csv`, which two
  unit tests read.
- Training databases, runtime logs, Grafana's database and Loki data.
- Local thesis TeX/PDF/Word drafts, presentation versions and demonstration video.
- Guest operating systems, installed guest packages, VM snapshots and any files
  stored only inside a guest disk.

To reproduce training or run the complete test suite, restore the corresponding
input files from a separate backup. Recorded data hashes and experiment lineage
are available in `experiments/*/results/`; they document the original inputs but
do not contain those inputs. Fresh training also requires the additional training
dependencies listed in the README.

Docker images using `latest` and unpinned dependencies may change over time. A
fresh deployment recreates the application from its definitions and may differ
from the old VM. Validate it again before using enforcement.

## Restore the thesis

Keep the thesis backup separately from the repository. The current local report
entry point at archival time is `DuongMinhTien_edited.tex`; retain its `figures/`
directory beside it. Install a suitable TeX distribution and compile from that
directory, for example with `latexmk -pdf DuongMinhTien_edited.tex`.

The legacy `main.tex` refers to `media/` images missing from the original checkout.
It is retained as historical source in the thesis backup and should not be used
as the main entry point without repairing those references. The backup includes
existing PDF outputs for comparison; no new compilation is implied.
