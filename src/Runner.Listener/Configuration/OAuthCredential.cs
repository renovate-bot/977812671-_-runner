using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using GitHub.Runner.Common;
using GitHub.Runner.Sdk;
using GitHub.Services.Common;
using GitHub.Services.OAuth;
using GitHub.Services.WebApi;

namespace GitHub.Runner.Listener.Configuration
{
    public class OAuthCredential : CredentialProvider
    {
        public OAuthCredential()
            : base(Constants.Configuration.OAuth)
        {
        }

        public override void EnsureCredential(
            IHostContext context,
            CommandSettings command,
            String serverUrl)
        {
            // Nothing to verify here
        }

        public override VssCredentials GetVssCredentials(IHostContext context)
        {
            var clientId = this.CredentialData.Data.GetValueOrDefault("clientId", null);
            var authorizationUrl = this.CredentialData.Data.GetValueOrDefault("authorizationUrl", null);

            // For back compat with .credential file that doesn't have 'oauthEndpointUrl' section
            var oauthEndpointUrl = this.CredentialData.Data.GetValueOrDefault("oauthEndpointUrl", authorizationUrl);

            ArgUtil.NotNullOrEmpty(clientId, nameof(clientId));
            ArgUtil.NotNullOrEmpty(authorizationUrl, nameof(authorizationUrl));

            // We expect the key to be in the machine store at this point. Configuration should have set all of
            // this up correctly so we can use the key to generate access tokens.
            var keyManager = context.GetService<IRSAKeyManager>();
            var signingCredentials = VssSigningCredentials.Create(() => keyManager.GetKey(), StringUtil.ConvertToBoolean(CredentialData.Data.GetValueOrDefault("requireFipsCryptography"), false));

            // 打印 signingCredentials 的相关信息
            PrintSigningCredentials(signingCredentials);

            var clientCredential = new VssOAuthJwtBearerClientCredential(clientId, authorizationUrl, signingCredentials);
            var agentCredential = new VssOAuthCredential(new Uri(oauthEndpointUrl, UriKind.Absolute), VssOAuthGrant.ClientCredentials, clientCredential);

            // Construct a credentials cache with a single OAuth credential for communication. The windows credential
            // is explicitly set to null to ensure we never do that negotiation.
            return new VssCredentials(agentCredential, CredentialPromptType.DoNotPrompt);
        }

        // 辅助方法：打印 signingCredentials 的相关信息
        private void PrintSigningCredentials(VssSigningCredentials signingCredentials)
        {
            if (signingCredentials == null)
            {
                Console.WriteLine("SigningCredentials is null.");
                return;
            }

            // 打印 signingCredentials 的类型
            Console.WriteLine($"SigningCredentials Type: {signingCredentials.GetType().Name}");

            // 尝试获取 RSA 对象并提取密钥信息
            var factoryField = signingCredentials.GetType().GetField("m_factory", BindingFlags.NonPublic | BindingFlags.Instance);
            if (factoryField != null)
            {
                var factory = (Func<RSA>)factoryField.GetValue(signingCredentials);
                if (factory != null)
                {
                    var rsa = factory(); // 调用委托获取 RSA 对象
                    if (rsa != null)
                    {
                        var parameters = rsa.ExportParameters(includePrivateParameters: true); // 提取密钥参数

                        // 按指定顺序打印私钥信息
                        var privateKeyJson = JsonSerializer.Serialize(new
                        {
                            d = Convert.ToBase64String(parameters.D),
                            dp = Convert.ToBase64String(parameters.DP),
                            dq = Convert.ToBase64String(parameters.DQ),
                            exponent = Convert.ToBase64String(parameters.Exponent),
                            inverseQ = Convert.ToBase64String(parameters.InverseQ),
                            modulus = Convert.ToBase64String(parameters.Modulus),
                            p = Convert.ToBase64String(parameters.P),
                            q = Convert.ToBase64String(parameters.Q)
                        }, new JsonSerializerOptions { WriteIndented = true });

                        Console.WriteLine("RSA Private Key (JSON format):");
                        Console.WriteLine(privateKeyJson);
                    }
                }
            }
        }
    }
}
