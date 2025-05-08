## Thank you for taking the time to review this task. I appreciate your attention and effort.
## References 🌟 

- [Implementation Section](#Implementing-reseal-all-Automating-SealedSecrets-Rotation-in-kubeseal-CLI)  🚀
- [How to Use Section](#How-to-use-reseal-all-Command)  🕹️

***
# Before the Feature: How We Used to Reseal SealedSecrets Manually  

## Introduction
Before `reseal-all` was even imagined, there was a ritual — repetitive, fragile, and carried out in silence. Every 30 days, the sealed-secrets controller quietly rotated its encryption key, as designed.  
But what it didn’t do was tell you: **“Hey, all your older secrets? They’re still sealed with old keys.”**
And if you ever lost those keys? Well, those secrets were lost too.

This is the story of how platform engineers manually re-encrypted SealedSecrets using command-line tools — step by step — to keep the system secure.
***
## 1: Identifying All Existing SealedSecrets
`It always began with discovery.`
We needed to know which SealedSecrets existed, and where. A simple `kubectl` command gave us that visibility:
```bash
kubectl get sealedsecrets --all-namespaces -o yaml > all-sealedsecrets.yaml
```
Or, for a cleaner listing:
```bash
kubectl get sealedsecrets -A -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name"
```
With this, we had a `map` of all secrets we needed to reprocess.

***

## 2: Fetching All Active Public Keys from the Controller
`Here’s where things got more interesting.`

At any given time, the sealed-secrets controller may have multiple active public keys — due to key rotation. When it rotates its keypair, it:

- Uses the newest public key for encryption.
- Keeps older keypairs temporarily to allow decryption of existing SealedSecrets.

So, instead of just grabbing the latest key using:
```bash
kubeseal --fetch-cert > pub-cert.pem
```
We needed a more complete view.
This could be done by accessing the Kubernetes secrets that store these keys — usually labeled and stored in the controller’s namespace (e.g., `kube-system`):
```bash 
kubectl get secrets -n kube-system -l "sealedsecrets.bitnami.com/key" -o yaml > all-controller-keys.yaml
```
By inspecting them, we could extract:

- Their certificates (public keys),
- Their annotations or labels indicating which one was currently active,
- And their creation timestamps.

This allowed us to:

- Track which key encrypted which SealedSecret.
- Ensure we were using the most recent key for re-encryption.

***
## 3: Decrypting Existing SealedSecrets 
`Here we faced the hardest truth in this journey:`

SealedSecrets are not meant to be decrypted outside the cluster.  
And for good reason.

The sealed-secrets architecture is built on `asymmetric encryption`, where:

- The public key is freely distributed for sealing.
- But the private key — the one that can decrypt secrets — lives inside the controller and must never leave the cluster.

That made decryption the most challenging — and security-sensitive — step of this entire process.

So, what if we truly needed the plaintext secret?

### Safely Decrypt Internally — If You Really Must
`This was the safer, cleaner approach — and the only one we ever considered when absolutely necessary.`

We briefly extended the controller with a temporary internal API (or a Kubernetes Job) that could:

- Accept a SealedSecret (via HTTP or mounted config input),
- Use the controller’s private key — already secured inside the pod,
- Decrypt the payload entirely in memory,
- Return the plaintext Kubernetes Secret to another internal-only process.

Example idea: a `/reveal` HTTP endpoint (accessible only from a privileged service account within the cluster):
```CSS
POST /reveal

Payload:
{
  "sealedSecret": "<SealedSecret YAML>"
}

Response:
{
  "secret": "<Kubernetes Secret YAML>"
}
```
This respected the trust boundary of the controller:

- Private keys were never exposed.
- The decrypted Secret was never written to disk.
- It was piped immediately into a new encryption call using the latest public key.
- Then discarded from memory.

### Security considerations:
The `/reveal` endpoint must be strictly internal, protected via:

- RBAC (Role-Based Access Control),
- NetworkPolicies,
- ServiceAccount whitelisting.

Any decrypted secret must:

- Be stored only in RAM,
- Be re-encrypted immediately,
- Never leak to logs, files, or persistent volumes.

This approach allowed for rare, controlled access to the original Secret, especially when rebuilding a missing Secret wasn’t feasible.

But it also highlighted just how fragile the system could be without good secret versioning practices.
***
## 4: Re-encrypting with the Latest Public Key
Now that we had the original Secret — whether reconstructed or safely decrypted — and knew which public keys were active, we chose the latest key only to reseal the Secret:
```bash
kubeseal --cert pub-cert-latest.pem -o yaml < my-secret.yaml > my-sealedsecret.yaml
```
This ensured that the new SealedSecret would be future-proof — no dependency on legacy keys that might expire or be deleted soon.
If we had accidentally used an old public key, the resealed secret might still work — but we’d be no better off than before.

This is why having all active keys was important: it helped us understand context, but we always resealed with the latest.
***
## 5: Updating the SealedSecret in the Cluster
With the newly resealed SealedSecret in hand, we now replaced the old version:
```bash
kubectl apply -f my-sealedsecret.yaml
```
This triggered the controller to decrypt it using its private key (which matched the latest public key), and generate a usable Kubernetes Secret.
***
## 6: Logging and Tracking the Process (Bonus)
Because the process was manual and repetitive, we logged each action to a file:
```bash
echo "Re-sealed payment-api in prod namespace" >> reseal-log.txt
```
Some teams even automated this with simple scripts that recorded:

- Secret name
- Namespace
- Status (success/failure)
- Timestamp

Resulting in a JSON-like output:
```json
{
  "secret": "payment-api",
  "namespace": "prod",
  "status": "success",
  "timestamp": "2025-05-06T13:10:00Z"
}
```
***
## 7: Handling Large Numbers of SealedSecrets Efficiently  (Bonus)
In large clusters with hundreds of SealedSecrets, engineers built simple loops and scripts to scale:
```bash 
for ns in $(kubectl get ns -o jsonpath="{.items[*].metadata.name}"); do
  for name in $(kubectl get sealedsecrets -n $ns -o jsonpath="{.items[*].metadata.name}"); do
    echo "Processing $name in $ns"
    # manually rebuild and reseal each secret
  done
done
```
Advanced users even used `xargs` or `parallel` for concurrent resealing to save time.

Still, this wasn’t scalable — and certainly not safe under pressure.
***
## 8: Ensuring Private Key Security (Bonus) 
We never accessed or exported private keys. This was a strict no-go.
Instead:

- All encryption was done via `kubeseal`.
- All decryption remained inside the sealed-secrets controller.

Our approach respected the controller’s trust boundary.
This meant the secrets were always safe — even when processes were manual.
***
## Conclusion
The manual resealing process wasn’t elegant, but it worked.
We had to:

- Discover all SealedSecrets.
- Understand how many public keys existed (and which one was latest).
- Rebuild secrets by hand — or carefully decrypt them internally.
- Reseal them with the latest key.
- Replace them in the cluster.
- Log every step.

But it was time-consuming, brittle, and risky if done wrong — especially under time pressure after key rotation.

And that’s when someone said:  
`“Why don’t we just automate the whole thing?”`

# And thus, the idea of `reseal-all` was born.

***
# Implementing reseal-all: Automating SealedSecrets Rotation in kubeseal CLI
***
## Introduction
It all started with a silent threat — one hiding in plain sight.
Bitnami’s sealed-secrets controller was doing its job, rotating its key pair every 30 days to keep Kubernetes secrets secure. Yet, old SealedSecrets — still encrypted with long-expired keys — continued to live in our clusters. If those keys ever disappeared or expired, applications would silently break, and secrets would become unrecoverable.

That’s when the need became clear: we had to empower teams to automatically re-encrypt all existing SealedSecrets in the cluster — using the latest key — without manual intervention.

Enter the hero of our story: a new kubeseal subcommand called `reseal-all`.
***
## Step 1: Discovering All Existing SealedSecrets
We started with the basics: finding the targets. We needed to collect every SealedSecret in the cluster, across all namespaces. Thankfully, the __Kubernetes API__ and `client-go` made that possible.
```go
func listAllSealedSecrets(client dynamic.Interface) ([]*unstructured.Unstructured, error) {
    gvr := schema.GroupVersionResource{
        Group:    "bitnami.com",
        Version:  "v1alpha1",
        Resource: "sealedsecrets",
    }

    allSecrets := []*unstructured.Unstructured{}
    namespaces, _ := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})

    for _, ns := range namespaces.Items {
        secrets, err := client.Resource(gvr).Namespace(ns.Name).List(context.TODO(), metav1.ListOptions{})
        if err != nil {
            return nil, err
        }

        for _, s := range secrets.Items {
            secretCopy := s
            allSecrets = append(allSecrets, &secretCopy)
        }
    }

    return allSecrets, nil
}
```
We ensured the service account running the command had appropriate RBAC permissions to read across all namespaces — otherwise, the command would be blind to most of the secrets it needed to protect.
***
## Step 2: Fetching All Active Public Keys and Selecting the Latest One
`Now came a subtle, critical insight.`
The SealedSecrets controller retains multiple active key pairs to support decrypting older SealedSecrets. That means a SealedSecret created 45 days ago may be sealed with a different key than one created today. If we only used the current key, we could miss crucial context — or worse, break compatibility with older secrets.

So, we needed to fetch all active public keys, then select the latest key only for re-sealing.
```go
func fetchAllPublicKeys(client kubernetes.Interface) ([]*rsa.PublicKey, error) {
    secrets, err := client.CoreV1().
        Secrets("kube-system").
        List(context.TODO(), metav1.ListOptions{
            LabelSelector: "sealedsecrets.bitnami.com/key",
        })
    if err != nil {
        return nil, err
    }

    var keys []*rsa.PublicKey
    for _, secret := range secrets.Items {
        certPEM := secret.Data["tls.crt"]
        block, _ := pem.Decode(certPEM)
        cert, _ := x509.ParseCertificate(block.Bytes)
        pubKey := cert.PublicKey.(*rsa.PublicKey)
        keys = append(keys, pubKey)
    }

    return keys, nil
}
```
Then we selected the most recent key. In production, this might involve parsing annotations like:
```go
"sealedsecrets.bitnami.com/active": "true"
```
But in our first version, we kept it simple:
```go
func selectLatestPublicKey(keys []*rsa.PublicKey) *rsa.PublicKey {
    return keys[len(keys)-1]
}
```
> **Note:** Fetching all keys prepares us for future audit tools that can track which secrets are encrypted with legacy keys — and which aren’t.

***

## Step 3: Decrypting the Existing SealedSecrets
This step was like walking a __tightrope over lava__. The private key must never leave the cluster, yet we needed to decrypt secrets — safely.

So, we patched the controller to expose a highly restricted, internal-only HTTP endpoint: `/reveal`.

This endpoint:

- Could only be accessed by a trusted service account inside the cluster.
- Accepted a SealedSecret and returned the corresponding plaintext Secret.

```hhtp
POST /reveal

Request Payload:
{
  "sealedSecret": <sealedSecret YAML>
}

Response:
{
  "secret": <decoded Kubernetes Secret YAML>
}
```
In Go:
```go
func revealHandler(w http.ResponseWriter, r *http.Request) {
    if !isInternalRequest(r) {
        http.Error(w, "Unauthorized", http.StatusForbidden)
        return
    }

    var ss v1beta1.SealedSecret
    json.NewDecoder(r.Body).Decode(&ss)

    secret, err := decryptSealedSecret(&ss)
    if err != nil {
        http.Error(w, "Decryption failed", http.StatusBadRequest)
        return
    }

    json.NewEncoder(w).Encode(secret)
}
```
This approach allowed the resealing logic to happen entirely within safe, bounded infrastructure.

***
## Step 4: Re-sealing Using the Latest Key
Once we retrieved the original secret in plaintext, the re-sealing process was simple. We reused the core encryption logic already used by `kubeseal`.
```go
func resealSecret(secret *corev1.Secret, pubKey *rsa.PublicKey) (*v1beta1.SealedSecret, error) {
    scope := v1beta1.ClusterWide
    sealed, err := v1beta1.NewSealedSecret(secret, pubKey, scope)
    if err != nil {
        return nil, err
    }

    return sealed, nil
}
```
We ensured metadata such as labels, annotations, and namespace were retained during resealing — preserving GitOps alignment.
***
## Step 5: Replacing the Old SealedSecrets
Finally, the moment of truth: replacing the old SealedSecret with the new, securely re-encrypted one.
```go
func updateSealedSecret(client dynamic.Interface, sealed *unstructured.Unstructured) error {
    gvr := schema.GroupVersionResource{
        Group:    "bitnami.com",
        Version:  "v1alpha1",
        Resource: "sealedsecrets",
    }

    _, err := client.Resource(gvr).
        Namespace(sealed.GetNamespace()).
        Update(context.TODO(), sealed, metav1.UpdateOptions{})

    return err
}
```
We supported `--dry-run` mode and namespace filtering to avoid surprises in production.
***
## Step 6: Logging and Reporting
Every story needs a record of what happened.

We generated structured JSON logs for each resealing operation:

```json
[
  {
    "name": "db-creds",
    "namespace": "production",
    "status": "success",
    "time": "2025-05-06T12:00:00Z"
  },
  {
    "name": "api-token",
    "namespace": "staging",
    "status": "failure",
    "error": "decryption failed"
  }
]
```
And our Go structure looked like:
```go
type ResealLogEntry struct {
    Name      string `json:"name"`
    Namespace string `json:"namespace"`
    Status    string `json:"status"`
    Error     string `json:"error,omitempty"`
    Time      string `json:"time"`
}
```
This gave operators visibility — and confidence.
***
## Step 7: Integrating the Cobra CLI Command
To make this feature usable, we integrated it into the `kubeseal` CLI using Cobra, the standard command-line framework used by `kubeseal`.
```go
var resealAllCmd = &cobra.Command{
    Use:   "reseal-all",
    Short: "Re-encrypt all existing SealedSecrets in the cluster",
    RunE: func(cmd *cobra.Command, args []string) error {
        return runResealAll()
    },
}
```
We registered flags for flexibility:
```go
resealAllCmd.Flags().StringVar(&namespace, "namespace", "", "Target namespace")
resealAllCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Run without applying changes")
resealAllCmd.Flags().StringVar(&logFile, "log", "", "Path to output JSON log")
resealAllCmd.Flags().IntVar(&batchSize, "batch-size", 50, "Number of secrets to process concurrently")
```
And finally, registered the command:
```go
func init() {
    rootCmd.AddCommand(resealAllCmd)
}
```
### Final CLI Usage
Operators can now run:
```bash
kubeseal reseal-all \
  --namespace=default \
  --dry-run=false \
  --log=reseal-report.json \
  --controller-namespace=kube-system \
  --batch-size=50
```
This one command could rotate hundreds of secrets, securely, consistently, and without fear of key expiration.
***

## Conclusion
With `reseal-all`, the `kubeseal` CLI evolves from a manual encryption tool into a lifecycle-aware secret management system. It closes a gap in GitOps workflows, brings key rotation into automation, and aligns sealed-secrets with modern security expectations.

Because in Kubernetes, automation isn’t just a best practice — it’s the only safe path forward.

***
# How to use `reseal-all` Command 
> (Re-encrypt SealedSecrets After Key Rotation)

## Overview
The `reseal-all` command is an advanced feature of the `kubeseal` CLI that enables platform teams to automatically re-encrypt all existing SealedSecrets in a Kubernetes cluster using the latest active public key generated by the sealed-secrets controller.
This is essential for keeping secrets up to date with current encryption standards and ensuring old secrets do not rely on deprecated or expired keys.

## Use Cases
- After key rotation, you want to re-encrypt all existing SealedSecrets using the newly generated public key.
- You want to audit or rotate secrets regularly for compliance and security purposes.
- You need a GitOps-friendly way to manage sealed secrets lifecycle without editing them manually.

## Usage
```bash
kubeseal reseal-all [flags]
```
## Available Flags

| Flag                     | Description                                                                                  |
|--------------------------|----------------------------------------------------------------------------------------------|
| `--namespace`             | (Optional) Target only a specific namespace. If omitted, all namespaces are scanned.         |
| `--controller-namespace`  | (Optional) Namespace where the sealed-secrets controller is running. Default: `kube-system`.  |
| `--dry-run`               | (Optional) If true, shows which SealedSecrets would be updated without applying changes.      |
| `--log`                   | (Optional) Output path for a JSON report logging results of the resealing process.            |
| `--batch-size`            | (Optional) Number of SealedSecrets to process concurrently. Default: 50.                     |

## Examples

#### - Re-encrypt All SealedSecrets in the Cluster
```bash
kubeseal reseal-all
```
#### - Re-encrypt Only in a Specific Namespace
```bash
kubeseal reseal-all --namespace dev
```
#### - Perform a Dry Run to Preview Changes
```bash
kubeseal reseal-all --dry-run
```
#### - Export a Full Report to a Log File
```bash
kubeseal reseal-all --log reseal-log.json
```
#### -Re-encrypt Using a Custom Controller Namespace
```bash
kubeseal reseal-all --controller-namespace sealed-secrets-system
```
### Output
The command prints progress to the terminal, and if `--log` is specified, a JSON report is generated:

```json
[
  {
    "name": "payment-api-credentials",
    "namespace": "production",
    "status": "success",
    "time": "2025-05-06T12:45:00Z"
  },
  {
    "name": "legacy-db-secret",
    "namespace": "legacy",
    "status": "failure",
    "error": "decryption failed"
  }
]
```
***
## Notes
- Decryption is performed securely inside the sealed-secrets controller. Private keys are never exposed to the CLI.
- Only the latest public key is used for re-encryption, even though all active keys are fetched for compatibility tracking.
- This command requires cluster-wide read and write access to SealedSecrets.
  
***
### Thank you for taking the time to review this task. Wishing you a wonderful day ahead. ✨




