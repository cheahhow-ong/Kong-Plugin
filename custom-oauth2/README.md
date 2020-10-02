# custom-oauth2

This plugin was customized based on [OAuth 2.0 Authentication](https://docs.konghq.com/hub/kong-inc/oauth2/), where the source code can be found [here](https://github.com/Kong/kong/tree/master/kong/plugins/oauth2).

## Customizations

WIP

## Getting Started

### Set up plugin (Kubernetes)

1. Run the following command to add the source code as `ConfigMap`.

  ```bash
  kubectl create configmap kong-plugin-custom-oauth2 --from-file=src/
  kubectl create configmap kong-plugin-custom-oauth2-migrations --from-file=src/migrations/
  kubectl create configmap kong-plugin-custom-oauth2-daos --from-file=src/daos/
  ```

2. (For Kong installed via [official Helm chart](https://github.com/Kong/charts)) Add plugin to `values.yaml`.

  ```yaml
  # The `name` property refers to the name of the ConfigMap or Secret
  # itself, while the `pluginName` refers to the name of the plugin as it appears in Kong.
  # The `pluginName` must match plugin name declared in handler.lua and schema.lua too.
  plugins:
    configMaps:
    - name: kong-plugin-custom-oauth2
      pluginName: custom-oauth2
      subdirectories:
      - name: kong-plugin-custom-oauth2-migrations
        path: migrations
      - name: kong-plugin-custom-oauth2-daos
        path: daos
  ```

3. Configure plugin by creating a `KongPlugin`, read more about `KongPlugin` resource [here](https://github.com/Kong/kubernetes-ingress-controller/blob/master/docs/guides/using-kongplugin-resource.md).

  ```bash
  # The `plugin` property refers to `pluginName` declared in values.yaml.
  echo 'apiVersion: configuration.konghq.com/v1
  kind: KongPlugin
  metadata:
    name: custom-oauth2
  config:
    auth_header_name: "Authorization"
    enable_client_credentials: true
    enable_password_grant: true
    global_credentials: true
    refresh_token_ttl: 300
    scopes:
    - firstTimeLogin
    - login
    - biometric
    - authenticated
    token_expiration: 60
    provision_key: "0123456789"
  plugin: custom-oauth2' | kubectl apply -f -
  ```

### Set up consumer

1. Create `secret` as Kong credential with `name`, `client_id`, `client_secret`, and `redirect_uris`. _Note: Do not use `KongCredential` as it is [deprecated](https://konghq.com/blog/kong-for-kubernetes-0-7-released/)._

  ```bash
  kubectl create secret generic wailoon-kong-oauth2 --from-literal=kongCredType=oauth2 --from-literal=name=wailoon --from-literal=client_id=wailoon --from-literal=client_secret='password' --from-literal=redirect_uris='https://ngcc-kong.liquiddelivery.net/serene/anything/something'
  ```

2. Create `KongConsumer` if not exist. Otherwise, attach the credential to the consumer.

  ```bash
  echo "apiVersion: configuration.konghq.com/v1
  kind: KongConsumer
  metadata:
    name: userX
  username: userX
  custom_id: userX
  credentials:
  - userX-kong-basic-auth
  - userX-kong-jwt
  - userX-kong-oauth2" | kubectl apply -f -
  ```
