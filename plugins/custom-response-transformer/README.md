# custom-response-transformer

This plugin was customized based on [Response Transformer](https://docs.konghq.com/hub/kong-inc/response-transformer/), where the source code can be found [here](https://github.com/Kong/kong/tree/master/kong/plugins/response-transformer).

## Customizations

* Added `:access()` phase to access request headers. Priority is set to 802 to store all request headers before being modified/removed by `request-transformer` (801).
* Body transformation is customized to reconstruct response body.
  * TODO: To add more descriptions
* Body transformation using `config.add.json` and `config.remove.json` is no longer supported.
* Header transformation using `config.append.header` and `config.remove.header` is still supported.
* Always clear `Content-Length` header.
* Added `:log()` phase.

## Getting Started

### Kubernetes

1. Run the following command to add the source code as `ConfigMap`.

  ```bash
  kubectl create configmap kong-plugin-custom-response-transformer --from-file=src/
  ```

2. (For Kong installed via [official Helm chart](https://github.com/Kong/charts)) Add plugin to `values.yaml`.

  ```yaml
  # The `name` property refers to the name of the ConfigMap or Secret
  # itself, while the `pluginName` refers to the name of the plugin as it appears in Kong.
  # The `pluginName` must match plugin name declared in handler.lua and schema.lua too.
  plugins:
    configMaps:
    - name: kong-plugin-custom-response-transformer
      pluginName: "custom-response-transformer"
  ```

3. Configure plugin by creating a `KongPlugin`, read more about `KongPlugin` resource [here](https://github.com/Kong/kubernetes-ingress-controller/blob/master/docs/guides/using-kongplugin-resource.md).

  ```bash
  # The `plugin` property refers to `pluginName` declared in values.yaml.
  echo '
  apiVersion: configuration.konghq.com/v1
  kind: KongPlugin
  metadata:
    name: custom-response-transformer
  plugin: custom-response-transformer
  ' | kubectl apply -f -
  ```
