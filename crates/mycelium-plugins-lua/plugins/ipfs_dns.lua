-- Only explicitly owned browser gateways qualify. `ipfs` RPC observations do not.
dns_policy = {
  aliases = function(context)
    return { ["ipfs-gateway"] = "ipfs" }
  end,
}
