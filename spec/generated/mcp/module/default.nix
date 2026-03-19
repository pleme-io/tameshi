# tameshi-mcp home-manager module -- MCP server + CLI
#
# Namespace: services.tameshi_mcp.*
#
# Provides:
#   - MCP server entry (consumed by claude/anvil for all AI agents)
#   - CLI binary in PATH
#   - Config file generation (~/.config/tameshi_mcp/tameshi_mcp.yaml)
#   - Env propagation: TAMESHI_MCP_CONFIG passed to MCP server process
#
# Usage:
#   services.tameshi_mcp.package = inputs.tameshi_mcp.packages.${system}.default;
#   services.tameshi_mcp.enable = true;
#   services.tameshi_mcp.mcp.enable = true;
{ hmHelpers }:
{
  lib,
  config,
  pkgs,
  ...
}:
with lib; let
  inherit (hmHelpers) mkMcpOptions mkMcpServerEntry;
  cfg = config.services.tameshi_mcp;
  mcpCfg = cfg.mcp;
  homeDir = config.home.homeDirectory;

  defaultApiKeyFile = "${homeDir}/.config/tameshi_mcp/api-key";

  resolvedApiKeyFile =
    if cfg.settings.apiKeyFile != null
    then cfg.settings.apiKeyFile
    else defaultApiKeyFile;

  configFile = pkgs.writeText "tameshi_mcp.yaml"
    (builtins.toJSON ({
      api_url = cfg.settings.apiUrl;
      api_key_file = resolvedApiKeyFile;
    }));

  mcpEnv = optionalAttrs cfg.settings.propagateApiKey {
    TAMESHI_MCP_CONFIG = "${configFile}";
  };
in {
  options.services.tameshi_mcp = {
    enable = mkEnableOption "tameshi_mcp -- CLI + MCP server";

    package = mkOption {
      type = types.package;
      description = ''
        The tameshi_mcp binary package. Must be set explicitly from your flake input:
          services.tameshi_mcp.package = inputs.tameshi_mcp.packages.''${system}.default;
      '';
    };

    mcp = mkMcpOptions {
      defaultPackage = pkgs.hello;
    };

    settings = {
      apiUrl = mkOption {
        type = types.str;
        default = "http://localhost:8080";
        description = "API base URL.";
      };

      apiKeyFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Path to file containing the API key.
          When null, defaults to ~/.config/tameshi_mcp/api-key.
        '';
      };

      propagateApiKey = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Pass config file path to the MCP server process via TAMESHI_MCP_CONFIG env.
          Ensures the MCP server can find the API key when launched by Claude
          Code or other MCP clients that don't inherit user environment.
        '';
      };
    };
  };

  config = mkMerge [
    {
      services.tameshi_mcp.mcp.package = mkDefault cfg.package;
    }

    (mkIf cfg.enable {
      home.packages = [ cfg.package ];

      xdg.configFile."tameshi_mcp/tameshi_mcp.yaml".source = configFile;
    })

    (mkIf mcpCfg.enable {
      services.tameshi_mcp.mcp.serverEntry = mkMcpServerEntry ({
        command = "${mcpCfg.package}/bin/tameshi_mcp";
      } // optionalAttrs (mcpEnv != {}) {
        env = mcpEnv;
      });
    })
  ];
}
