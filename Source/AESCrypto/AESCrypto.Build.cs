// Some copyright should be here...

using UnrealBuildTool;

using System.IO;

public class AESCrypto : ModuleRules
{
	public AESCrypto(ReadOnlyTargetRules Target) : base(Target)
	{
		PCHUsage = ModuleRules.PCHUsageMode.UseExplicitOrSharedPCHs;
		
		PublicIncludePaths.AddRange(
			new string[] {
				// ... add public include paths required here ...
			}
			);
				
		
		PrivateIncludePaths.AddRange(
			new string[] {
				// ... add other private include paths required here ...
			}
			);
			
		
		PublicDependencyModuleNames.AddRange(
			new string[]
			{
				"Core",
				// ... add other public dependencies that you statically link with here ...
			}
			);
			
		
		PrivateDependencyModuleNames.AddRange(
			new string[]
			{
				"CoreUObject",
				"Engine",
				"Slate",
				"SlateCore",
				// ... add private dependencies that you statically link with here ...	
			}
			);
		
		
		DynamicallyLoadedModuleNames.AddRange(
			new string[]
			{
				// ... add any modules that your module loads dynamically here ...
			}
			);
        PublicIncludePaths.Add(Path.Combine(ModuleDirectory, "../ThirdParty/include"));

        if (Target.Platform == UnrealTargetPlatform.Android)
        {
            PrivateDependencyModuleNames.AddRange(new string[] { "Launch" });

            string PluginPath = Utils.MakePathRelativeTo(ModuleDirectory, Target.RelativeEnginePath);
            AdditionalPropertiesForReceipt.Add("AndroidPlugin", Path.Combine(PluginPath, "AESCrypto_APL.xml"));

            PublicAdditionalLibraries.Add(Path.Combine(ModuleDirectory, "../ThirdParty/lib/armeabi-v7a/libcryptopp.so"));


        }
        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            PublicAdditionalLibraries.Add(Path.Combine(ModuleDirectory, "../ThirdParty/lib/Windows/cryptlib.lib"));
        }
        bEnableUndefinedIdentifierWarnings = false;
        bEnableExceptions = true;
        bUseRTTI = true;

    }
}
