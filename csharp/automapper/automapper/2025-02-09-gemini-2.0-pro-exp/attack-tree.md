# Attack Tree Analysis for automapper/automapper

Objective: Execute Arbitrary Code OR Exfiltrate Sensitive Data via AutoMapper

## Attack Tree Visualization

```
                                     [Attacker's Goal: Execute Arbitrary Code OR Exfiltrate Sensitive Data via AutoMapper]
                                                                    |
                                        -------------------------------------------------------------------------
                                        |
                  [1. Configuration-Based Attacks]
                                        |
         -------------------***-------------------------
         |                       |
[***1.1 Unsafe Type      [1.2 Malicious
  Resolution***]           Configuration]
         |                       |
  -------|-------       ---***---|-------
  |             |       |             |
[***1.1.1***]           [***1.2.1***]   [***1.2.2***]
Allowing                Loading       Specifying
[***Unsafe              [***External  [***Dangerous
Types***]               Config        Functions***]
in                      Files***]     in
`ResolveUsing`           (e.g.,        `MapFrom`
or                      XML,          (e.g.,
`ConvertUsing`           JSON)         [***Shell
                                        Commands)***]
```

## Attack Tree Path: [1. Configuration-Based Attacks](./attack_tree_paths/1__configuration-based_attacks.md)

This category focuses on manipulating AutoMapper's configuration to achieve malicious goals. The configuration itself becomes the attack vector.

## Attack Tree Path: [1.1 Unsafe Type Resolution](./attack_tree_paths/1_1_unsafe_type_resolution.md)

Description: AutoMapper allows resolving types dynamically during the mapping process. If an attacker can control which type is being resolved, they can potentially instantiate arbitrary classes, leading to code execution.

## Attack Tree Path: [1.1.1 Allowing [***Unsafe Types***] in `ResolveUsing` or `ConvertUsing`](./attack_tree_paths/1_1_1_allowing__unsafe_types__in__resolveusing__or__convertusing_.md)

Description: This is the most direct way to exploit unsafe type resolution. If the application allows user-supplied input to determine the type passed to `ResolveUsing` or `ConvertUsing`, an attacker can specify a malicious type. This malicious type could have code in its constructor, static initializer, or other methods that gets executed when the type is instantiated by AutoMapper.
Example:
```csharp
// Vulnerable code:
public class MyController : Controller
{
    public IActionResult MapData(string typeName, string sourceData)
    {
        Type targetType = Type.GetType(typeName); // User controls typeName!
        var source = JsonConvert.DeserializeObject<SourceType>(sourceData);
        var destination = Mapper.Map(source, typeof(SourceType), targetType);
        return Ok(destination);
    }
}

// Attacker provides typeName: "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
// Attacker provides sourceData (doesn't matter in this case)
// AutoMapper instantiates System.Diagnostics.Process, which can then be used to start a new process (e.g., a shell).
```
Mitigation:
*   Strictly avoid using user input to determine types.
*   If dynamic type resolution is absolutely necessary, use a whitelist of allowed types.  *Never* use a blacklist.
*   Sanitize and validate any input that *might* influence type resolution, even indirectly.

## Attack Tree Path: [1.2 Malicious Configuration](./attack_tree_paths/1_2_malicious_configuration.md)

Description: This involves providing AutoMapper with a configuration that contains malicious instructions. This can be done by loading configuration from untrusted sources or by allowing dangerous functions to be specified within the configuration.

## Attack Tree Path: [1.2.1 Loading [***External Config Files***] (e.g., XML, JSON)](./attack_tree_paths/1_2_1_loading__external_config_files___e_g___xml__json_.md)

Description: If AutoMapper's configuration is loaded from an external file (XML, JSON, etc.), and an attacker can modify that file, they can inject arbitrary mapping rules, including those that lead to unsafe type resolution or other vulnerabilities.
Example:
```xml
<!-- Malicious XML configuration -->
<configuration>
  <typeMaps>
    <typeMap sourceType="MyApplication.SourceType" destinationType="System.Diagnostics.Process, System">
      <memberMaps>
        <memberMap source="SomeProperty" destination="StartInfo.FileName">
          <value>cmd.exe</value>
        </memberMap>
        <memberMap source="AnotherProperty" destination="StartInfo.Arguments">
          <value>/c calc.exe</value>  <!-- Start the calculator -->
        </memberMap>
      </memberMaps>
    </typeMap>
  </typeMaps>
</configuration>
```
Mitigation:
*   Avoid loading AutoMapper configuration from external files. Hardcode configurations whenever possible.
*   If external configuration is *absolutely* necessary:
    *   Use strong access controls (e.g., file system permissions) to prevent unauthorized modification.
    *   Implement integrity checks (e.g., digital signatures, checksums) to ensure the configuration file hasn't been tampered with.
    *   Use a secure configuration store (e.g., a secrets management service) instead of plain text files.

## Attack Tree Path: [1.2.2 Specifying [***Dangerous Functions***] in `MapFrom` (e.g., [***Shell Commands***])](./attack_tree_paths/1_2_2_specifying__dangerous_functions__in__mapfrom___e_g____shell_commands__.md)

Description: The `MapFrom` method allows specifying an expression to map a source property to a destination property.  If this expression is constructed using untrusted input, and the expression allows arbitrary code execution (e.g., invoking system commands), this is a critical code injection vulnerability.
Example:
```csharp
// Vulnerable code:
public class MyProfile : Profile
{
    public MyProfile()
    {
        CreateMap<Source, Destination>()
            .ForMember(dest => dest.Result, opt => opt.MapFrom(src => RunCommand(src.UserInput))); // UserInput is untrusted!
    }

    private string RunCommand(string command)
    {
        // DO NOT DO THIS! This is just for demonstration.
        return Process.Start("cmd.exe", $'/c {command}').StandardOutput.ReadToEnd();
    }
}
```
Mitigation:
*   Never construct `MapFrom` expressions using untrusted input.
*   If you need to use data from the source object in a `MapFrom` expression, ensure that the data is properly validated and sanitized *before* being used in the expression.  Do *not* rely on AutoMapper to sanitize the input.
*   Avoid using `MapFrom` with expressions that execute external code or interact with the operating system.
*   Use safer alternatives, such as custom resolvers (with careful auditing) or direct property assignments, whenever possible.

