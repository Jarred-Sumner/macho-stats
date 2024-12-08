"use client";

import {
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Clock,
  FileCode,
  FileText,
  Flag,
  Hash,
  Info,
  Key,
  Lock,
  Server,
  Shield,
  Upload,
  XCircle,
} from "lucide-react";
import React, { useState } from "react";

// Mach-O Constants
const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const LC_DYLD_CHAINED_FIXUPS = 0x80000034;
const LC_SEGMENT_64 = 0x19;
const LC_CODE_SIGNATURE = 0x1d;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const LC_VERSION_MIN_MACOSX = 0x24;
const LC_BUILD_VERSION = 0x32;
const LC_UUID = 0x1b;
const LC_MAIN = 0x28;

// Code Signing Constants
const CSMAGIC_REQUIREMENT = 0xfade0c00;
const CSMAGIC_REQUIREMENTS = 0xfade0c01;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1;
const CSMAGIC_BLOBWRAPPER = 0xfade0b01;
const CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171;
const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xfade7172;

// CPU Types
const CPU_TYPE_MAP = {
  0x7: "Intel x86",
  0x1000007: "Intel x64",
  0xc: "ARM32",
  0x100000c: "ARM64",
  0x1: "VAX",
  0x6: "MC68000",
  0xa: "MC88000",
  0xb: "HPPA",
  0xe: "SPARC",
  0x12: "PowerPC",
  0x1000012: "PowerPC 64",
};

// Load Command Types
const LOAD_COMMAND_MAP = {
  0x1: "LC_SEGMENT",
  0x2: "LC_SYMTAB",
  0x19: "LC_SEGMENT_64",
  0x1d: "LC_CODE_SIGNATURE",
  0x80000034: "LC_DYLD_CHAINED_FIXUPS",
  0x21: "LC_ENCRYPTION_INFO",
  0x2c: "LC_ENCRYPTION_INFO_64",
  0x24: "LC_VERSION_MIN_MACOSX",
  0x32: "LC_BUILD_VERSION",
  0x1b: "LC_UUID",
  0x28: "LC_MAIN",
  0xc: "LC_LOAD_DYLIB",
  0xd: "LC_ID_DYLIB",
  0xe: "LC_LOAD_DYLINKER",
  0x22: "LC_DYLD_INFO",
  0x80000022: "LC_DYLD_INFO_ONLY",
};

// Command Type Descriptions
const COMMAND_DESCRIPTIONS = {
  LC_SEGMENT:
    "Defines a segment of the binary containing sections of code or data",
  LC_SYMTAB: "Contains symbol table information for linking and debugging",
  LC_SEGMENT_64: "64-bit version of LC_SEGMENT",
  LC_CODE_SIGNATURE:
    "Contains code signing information to verify binary integrity",
  LC_DYLD_CHAINED_FIXUPS:
    "Contains information about chained fixups for dynamic linking",
  LC_ENCRYPTION_INFO: "Specifies encrypted segments in iOS binaries",
  LC_ENCRYPTION_INFO_64: "64-bit version of LC_ENCRYPTION_INFO",
  LC_VERSION_MIN_MACOSX: "Specifies minimum macOS version required",
  LC_BUILD_VERSION: "Specifies build version and platform requirements",
  LC_UUID: "Unique identifier for the binary",
  LC_MAIN: "Specifies the entry point of the binary",
  LC_LOAD_DYLIB: "Specifies a dynamic library dependency",
  LC_ID_DYLIB: "Specifies the identification of a dynamic library",
  LC_LOAD_DYLINKER: "Specifies the dynamic linker to be used",
  LC_DYLD_INFO: "Contains information for the dynamic linker",
  LC_DYLD_INFO_ONLY: "Same as LC_DYLD_INFO but required by the dynamic linker",
};

// File Types
const FILE_TYPE_MAP = {
  0x1: "MH_OBJECT",
  0x2: "MH_EXECUTE",
  0x3: "MH_FVMLIB",
  0x4: "MH_CORE",
  0x5: "MH_PRELOAD",
  0x6: "MH_DYLIB",
  0x7: "MH_DYLINKER",
  0x8: "MH_BUNDLE",
  0x9: "MH_DYLIB_STUB",
  0xa: "MH_DSYM",
  0xb: "MH_KEXT_BUNDLE",
};

// Code Signing Flag Descriptions
const CS_FLAG_MAP = {
  "0x1": "HOST_PROTECTION",
  "0x2": "RESTRICTED",
  "0x4": "ENFORCEMENT",
  "0x8": "REQUIRES_LV",
  "0x10": "HARD",
  "0x20": "KILL",
  "0x40": "CHECK_EXPIRATION",
  "0x80": "RESTRICT_DYLD",
  "0x100": "RUNTIME",
  "0x200": "LINKER_SIGNED",
  "0x400": "ALLOWED_MACHO",
  "0x800": "EXEC_SET_HARD",
  "0x1000": "EXEC_SET_KILL",
  "0x2000": "EXEC_SET_ENFORCEMENT",
  "0x4000": "EXEC_INHERIT_SIP",
};

// Platform Types
const PLATFORM_MAP = {
  1: "macOS",
  2: "iOS",
  3: "tvOS",
  4: "watchOS",
  5: "bridgeOS",
  6: "macCatalyst",
  7: "iOSSimulator",
  8: "tvOSSimulator",
  9: "watchOSSimulator",
};

class Reader {
  private buffer: ArrayBuffer;
  private offset: number;
  private view: DataView;
  private isLittleEndian: boolean;

  constructor(buffer: ArrayBuffer, littleEndian: boolean = true) {
    this.buffer = buffer;
    this.offset = 0;
    this.view = new DataView(buffer);
    this.isLittleEndian = littleEndian;
  }

  readUInt32(): number {
    if (this.offset + 4 > this.buffer.byteLength) {
      throw new Error(
        `Buffer overflow at offset 0x${this.offset.toString(16)}`
      );
    }
    const value = this.view.getUint32(this.offset, this.isLittleEndian);
    this.offset += 4;
    return value;
  }

  readUInt32BE(): number {
    if (this.offset + 4 > this.buffer.byteLength) {
      throw new Error(
        `Buffer overflow at offset 0x${this.offset.toString(16)}`
      );
    }
    const value = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return value;
  }

  readUInt16(): number {
    const value = this.view.getUint16(this.offset, this.isLittleEndian);
    this.offset += 2;
    return value;
  }

  readUInt8(): number {
    const value = this.view.getUint8(this.offset);
    this.offset += 1;
    return value;
  }

  readString(length: number): string {
    const bytes = new Uint8Array(this.buffer, this.offset, length);
    let str = "";
    for (let i = 0; i < length; i++) {
      if (bytes[i] === 0) break;
      str += String.fromCharCode(bytes[i]);
    }
    this.offset += length;
    return str;
  }

  readNullTerminatedString(): string {
    let str = "";
    while (this.offset < this.buffer.byteLength) {
      const byte = this.view.getUint8(this.offset);
      if (byte === 0) {
        this.offset++;
        break;
      }
      str += String.fromCharCode(byte);
      this.offset++;
    }
    return str;
  }

  seek(offset: number): void {
    if (offset > this.buffer.byteLength) {
      throw new Error(`Seek beyond buffer bounds: 0x${offset.toString(16)}`);
    }
    this.offset = offset;
  }

  skip(bytes: number): void {
    this.seek(this.offset + bytes);
  }

  peekUInt32(): number {
    return this.view.getUint32(this.offset, this.isLittleEndian);
  }

  getCurrentOffset(): number {
    return this.offset;
  }

  getRemainingBytes(): number {
    return this.buffer.byteLength - this.offset;
  }

  readBytes(length: number): Uint8Array {
    const bytes = new Uint8Array(
      this.buffer.slice(this.offset, this.offset + length)
    );
    this.offset += length;
    return bytes;
  }
}

interface TreeNodeProps {
  label: string;
  children?: React.ReactNode;
  defaultOpen?: boolean;
  icon?: React.ReactNode;
}

const TreeNode: React.FC<TreeNodeProps> = ({
  label,
  children,
  defaultOpen = false,
  icon,
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const hasChildren = React.Children.count(children) > 0;

  return (
    <div className="ml-4">
      <div
        className="flex items-center space-x-1 cursor-pointer py-1 hover:bg-gray-50"
        onClick={() => hasChildren && setIsOpen(!isOpen)}
      >
        {hasChildren ? (
          isOpen ? (
            <ChevronDown className="text-gray-500" size={16} />
          ) : (
            <ChevronRight className="text-gray-500" size={16} />
          )
        ) : (
          <div className="w-4" />
        )}
        {icon && <div className="text-gray-600">{icon}</div>}
        <span className="font-mono">{label}</span>
      </div>
      {isOpen && <div className="ml-2">{children}</div>}
    </div>
  );
};

interface CodeSignatureValidation {
  isValid: boolean;
  message: string;
  details: {
    hashAlgorithm: string;
    version: string;
    flags: string[];
    platform: string;
    teamId?: string;
    entitlements?: object;
    sealed: boolean;
    timestamped: boolean;
  };
  severity: "success" | "warning" | "error";
}

interface SecurityAssessment {
  level: "high" | "medium" | "low";
  message: string;
  details: string[];
}

const MachoAnalyzer: React.FC = () => {
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [debugLog, setDebugLog] = useState<string[]>([]);
  const [signatureValidation, setSignatureValidation] =
    useState<CodeSignatureValidation | null>(null);
  const [securityAssessment, setSecurityAssessment] =
    useState<SecurityAssessment | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [selectedView, setSelectedView] = useState<"analysis" | "debug">(
    "analysis"
  );

  const log = (msg: string): void => {
    setDebugLog((prev) => [...prev, msg]);
  };

  const getFlagDescriptions = (
    flags: number,
    flagMap: Record<string, string>
  ): string[] => {
    return Object.entries(flagMap)
      .filter(([value]) => flags & parseInt(value))
      .map(([_, desc]) => desc);
  };

  const validateCodeSignature = (signature: any): CodeSignatureValidation => {
    if (!signature) {
      return {
        isValid: false,
        message: "No code signature found",
        details: {
          hashAlgorithm: "None",
          version: "N/A",
          flags: [],
          platform: "Unknown",
          sealed: false,
          timestamped: false,
        },
        severity: "error",
      };
    }

    const codeDirectory = signature.find(
      (blob: any) => blob.type === "CodeDirectory"
    );

    if (!codeDirectory) {
      return {
        isValid: false,
        message: "No CodeDirectory found in signature",
        details: {
          hashAlgorithm: "None",
          version: "N/A",
          flags: [],
          platform: "Unknown",
          sealed: false,
          timestamped: false,
        },
        severity: "error",
      };
    }

    const hashTypes = ["SHA1", "SHA256", "SHA256/384"];
    const hashAlgorithm = hashTypes[codeDirectory.data.hashType] || "Unknown";

    // Get flag descriptions
    const flagDescriptions = getFlagDescriptions(
      codeDirectory.data.flags,
      CS_FLAG_MAP
    );

    // Check for required security flags
    const hasRequiredFlags =
      codeDirectory.data.flags & 0x4 && // CS_ENFORCEMENT
      codeDirectory.data.flags & 0x10 && // CS_HARD
      codeDirectory.data.flags & 0x20; // CS_KILL

    // Check hash type (0 = SHA1, 1 = SHA256, 2 = SHA256/384)
    const hasStrongHash = [1, 2].includes(codeDirectory.data.hashType);

    // Validate version (should be >= 0x20400 for best security)
    const hasModernVersion = codeDirectory.data.version >= 0x20400;

    // Check for sealed resources
    const isSealed = codeDirectory.data.flags & 0x10;

    // Check for timestamp
    const hasTimestamp = signature.some(
      (blob: any) => blob.type === "TimestampBlock"
    );

    let severity: "success" | "warning" | "error" = "success";
    let validationMessage = "Code signature appears valid";

    if (!hasStrongHash || !hasRequiredFlags || !hasModernVersion) {
      severity = "error";
      if (!hasRequiredFlags) {
        const missingFlags = [];
        if (codeDirectory.data.flags & 0x4) {
          missingFlags.push("ENFORCEMENT flag");
        }
        if (!(codeDirectory.data.flags & 0x10)) {
          missingFlags.push("HARD flag");
        }
        if (!(codeDirectory.data.flags & 0x20)) {
          missingFlags.push("KILL flag");
        }
        severity = "warning";
        validationMessage = `Code signature is missing flags: ${missingFlags.join(
          ", "
        )}`;
      } else if (!hasStrongHash) {
        severity = "error";
        ("Code signature is using an outdated hash algorithm");
      } else if (!hasModernVersion) {
        validationMessage = "Code signature is using an outdated version";
      }
    } else if (!isSealed || !hasTimestamp) {
      severity = "warning";
      validationMessage = "Code signature could be strengthened";
    }

    return {
      isValid: hasStrongHash && hasRequiredFlags,
      message: validationMessage,
      details: {
        hashAlgorithm,
        version: `0x${codeDirectory.data.version.toString(16)}`,
        flags: flagDescriptions,
        platform: PLATFORM_MAP[codeDirectory.data.platform] || "Unknown",
        teamId: codeDirectory.data.teamId,
        entitlements: codeDirectory.data.entitlements,
        sealed: isSealed,
        timestamped: hasTimestamp,
      },
      severity,
    };
  };

  const analyzeCodeSignature = (
    reader: Reader,
    dataoff: number,
    datasize: number
  ) => {
    const startOffset = reader.getCurrentOffset();
    const magic = reader.readUInt32BE();

    if (magic !== CSMAGIC_EMBEDDED_SIGNATURE) {
      throw new Error(`Invalid signature magic: 0x${magic.toString(16)}`);
    }

    const length = reader.readUInt32BE();
    const count = reader.readUInt32BE();

    log(`SuperBlob at 0x${startOffset.toString(16)}:`);
    log(` Magic: 0x${magic.toString(16)}`);
    log(` Length: ${length}`);
    log(` Count: ${count}`);

    const blobs = [];

    // Read blob headers
    for (let i = 0; i < count; i++) {
      const type = reader.readUInt32BE();
      const offset = reader.readUInt32BE();
      blobs.push({ type, offset });
    }

    // Now read each blob
    const results = [];
    for (const blob of blobs) {
      reader.seek(startOffset + blob.offset);
      const blobMagic = reader.readUInt32BE();
      const blobLength = reader.readUInt32BE();

      log(`Blob at offset 0x${(startOffset + blob.offset).toString(16)}:`);
      log(` Type: 0x${blob.type.toString(16)}`);
      log(` Magic: 0x${blobMagic.toString(16)}`);
      log(` Length: ${blobLength}`);

      if (blobMagic === CSMAGIC_CODEDIRECTORY) {
        const version = reader.readUInt32BE();
        const flags = reader.readUInt32BE();
        const hashOffset = reader.readUInt32BE();
        const identOffset = reader.readUInt32BE();
        const nSpecialSlots = reader.readUInt32BE();
        const nCodeSlots = reader.readUInt32BE();
        const codeLimit = reader.readUInt32BE();
        const hashSize = reader.readUInt8();
        const hashType = reader.readUInt8();
        const platform = reader.readUInt8();
        const pageSize = reader.readUInt8();
        reader.readUInt32(); // spare1

        // Read team ID if version supports it
        let teamId;
        if (version >= 0x20200) {
          const teamIdOffset = reader.readUInt32BE();
          if (teamIdOffset) {
            const currentPos = reader.getCurrentOffset();
            reader.seek(startOffset + blob.offset + teamIdOffset);
            teamId = reader.readNullTerminatedString();
            reader.seek(currentPos);
          }
        }

        results.push({
          type: "CodeDirectory",
          data: {
            magic: blobMagic,
            length: blobLength,
            version,
            flags,
            hashOffset,
            identOffset,
            nSpecialSlots,
            nCodeSlots,
            codeLimit,
            hashSize,
            hashType,
            platform,
            pageSize,
            teamId,
          },
        });
      } else if (blobMagic === CSMAGIC_EMBEDDED_ENTITLEMENTS) {
        const entitlementData = reader.readBytes(blobLength - 8);
        const textDecoder = new TextDecoder();
        const entitlements = JSON.parse(textDecoder.decode(entitlementData));
        results.push({
          type: "Entitlements",
          data: entitlements,
        });
      }
    }

    return results;
  };

  const analyzeMachO = async (buffer: ArrayBuffer) => {
    try {
      setDebugLog([]);
      setIsAnalyzing(true);
      const reader = new Reader(buffer);
      const result: any = {
        header: {},
        segments: [],
        codeSign: null,
        encryption: null,
        entitlements: null,
        uuid: null,
        minVersion: null,
        buildVersion: null,
        commands: [], // New field to store command details
      };

      const magic = reader.readUInt32();
      log(`Magic: 0x${magic.toString(16)}`);

      if (magic !== MH_MAGIC_64 && magic !== MH_CIGAM_64) {
        throw new Error("Not a 64-bit Mach-O file");
      }

      // Set endianness based on magic
      reader.isLittleEndian = magic === MH_MAGIC_64;

      const cpu = reader.readUInt32();
      const cpuSub = reader.readUInt32();
      const fileType = reader.readUInt32();
      const ncmds = reader.readUInt32();
      const sizeofcmds = reader.readUInt32();
      const flags = reader.readUInt32();

      result.header = {
        cpu: CPU_TYPE_MAP[cpu] || `Unknown (0x${cpu.toString(16)})`,
        fileType:
          FILE_TYPE_MAP[fileType] || `Unknown (0x${fileType.toString(16)})`,
        flags: flags,
        commands: ncmds,
      };

      log(`CPU Type: ${result.header.cpu}`);
      log(`File Type: ${result.header.fileType}`);
      log(`Number of commands: ${ncmds}`);

      let currentOffset = 32;
      for (let i = 0; i < ncmds; i++) {
        reader.seek(currentOffset);
        const cmd = reader.readUInt32();
        const cmdsize = reader.readUInt32();

        const cmdName =
          LOAD_COMMAND_MAP[cmd] || `Unknown (0x${cmd.toString(16)})`;
        const cmdDescription =
          COMMAND_DESCRIPTIONS[cmdName] || "Unknown command type";

        // Store command details
        result.commands.push({
          name: cmdName,
          description: cmdDescription,
          size: cmdsize,
          offset: currentOffset,
        });

        log(`Command ${i}: ${cmdName} (size: ${cmdsize})`);
        log(`Description: ${cmdDescription}`);

        if (cmd === LC_CODE_SIGNATURE) {
          const dataoff = reader.readUInt32();
          const datasize = reader.readUInt32();
          log(
            `Code signature at offset 0x${dataoff.toString(
              16
            )} size ${datasize}`
          );

          const currentPos = reader.getCurrentOffset();
          reader.seek(dataoff);
          result.codeSign = analyzeCodeSignature(reader, dataoff, datasize);
          reader.seek(currentPos);

          // Validate signature
          const validation = validateCodeSignature(result.codeSign);
          setSignatureValidation(validation);
        } else if (
          cmd === LC_ENCRYPTION_INFO ||
          cmd === LC_ENCRYPTION_INFO_64
        ) {
          const cryptoff = reader.readUInt32();
          const cryptsize = reader.readUInt32();
          const cryptid = reader.readUInt32();

          result.encryption = {
            offset: cryptoff,
            size: cryptsize,
            id: cryptid,
            encrypted: cryptid !== 0,
          };
        } else if (cmd === LC_UUID) {
          const uuid = Array.from(reader.readBytes(16))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          result.uuid = uuid;
        } else if (cmd === LC_VERSION_MIN_MACOSX) {
          const version = reader.readUInt32();
          const sdk = reader.readUInt32();
          result.minVersion = {
            version: `${(version >> 16) & 0xff}.${(version >> 8) & 0xff}.${
              version & 0xff
            }`,
            sdk: `${(sdk >> 16) & 0xff}.${(sdk >> 8) & 0xff}.${sdk & 0xff}`,
          };
        } else if (cmd === LC_BUILD_VERSION) {
          const platform = reader.readUInt32();
          const minos = reader.readUInt32();
          const sdk = reader.readUInt32();
          const ntools = reader.readUInt32();

          result.buildVersion = {
            platform: PLATFORM_MAP[platform] || "Unknown",
            minOS: `${(minos >> 16) & 0xff}.${(minos >> 8) & 0xff}.${
              minos & 0xff
            }`,
            sdk: `${(sdk >> 16) & 0xff}.${(sdk >> 8) & 0xff}.${sdk & 0xff}`,
            tools: [],
          };

          for (let t = 0; t < ntools; t++) {
            const tool = reader.readUInt32();
            const version = reader.readUInt32();
            result.buildVersion.tools.push({
              tool: `0x${tool.toString(16)}`,
              version: `${(version >> 16) & 0xff}.${(version >> 8) & 0xff}.${
                version & 0xff
              }`,
            });
          }
        }

        currentOffset += cmdsize;
      }

      // Perform security assessment
      const assessment: SecurityAssessment = {
        level: "low",
        message: "Multiple security concerns detected",
        details: [],
      };

      if (!result.codeSign) {
        assessment.details.push("Binary is not code signed");
      }

      if (result.encryption?.encrypted) {
        assessment.details.push("Binary is encrypted");
      }

      if (signatureValidation?.severity === "error") {
        assessment.details.push("Code signature validation failed");
      }

      if (assessment.details.length === 0) {
        assessment.level = "high";
        assessment.message = "No major security concerns detected";
      } else if (
        assessment.details.length === 1 &&
        signatureValidation?.severity === "warning"
      ) {
        assessment.level = "medium";
        assessment.message = "Minor security concerns detected";
      }

      setSecurityAssessment(assessment);
      setAnalysisResult(result);
      setError(null);

      // Store analysis data in URL hash
      const hashData = {
        result,
        signature: signatureValidation,
        security: assessment,
        log: debugLog,
        view: selectedView,
        isAnalyzing: isAnalyzing,
        error: error,
        securityAssessment: securityAssessment,
        analysisResult: analysisResult,
        signatureValidation: signatureValidation,
      };

      // Custom replacer function to handle special types
      const replacer = (key: string, value: any) => {
        if (typeof value === "bigint") {
          return value.toString() + "n";
        }
        if (value instanceof Set) {
          return {
            _type: "Set",
            values: Array.from(value),
          };
        }
        if (value instanceof Map) {
          return {
            _type: "Map",
            entries: Array.from(value.entries()),
          };
        }
        if (value instanceof Date) {
          return {
            _type: "Date",
            value: value.toISOString(),
          };
        }
        if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
          return {
            _type: "ArrayBuffer",
            data: Array.from(
              new Uint8Array(
                value instanceof ArrayBuffer ? value : value.buffer
              )
            ),
          };
        }
        return value;
      };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      log(`Error: ${errorMessage}`);
      setError(errorMessage);
      setAnalysisResult(null);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      const buffer = e.target?.result as ArrayBuffer;
      if (buffer) {
        await analyzeMachO(buffer);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  return (
    <div className="p-4 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-4 flex items-center">
        <FileCode className="mr-2" />
        Mach-O Binary Analyzer
      </h1>
      {!analysisResult ? (
        <div className="flex items-center justify-left h-96">
          <label className="flex flex-col items-center px-20 py-16 bg-blue-500 text-white rounded-lg cursor-pointer hover:bg-blue-600 transition-colors text-center">
            <Upload className="mb-4" size={48} />
            <span className="text-xl font-medium">Upload Mach-O File</span>
            <span className="text-sm opacity-75 mt-2">
              Click or drag and drop
            </span>
            <input type="file" className="hidden" onChange={handleFileUpload} />
          </label>
        </div>
      ) : (
        <div className="flex items-center space-x-4">
          <label className="flex items-center px-4 py-2 bg-blue-500 text-white rounded-lg cursor-pointer hover:bg-blue-600 transition-colors">
            <Upload className="mr-2" size={20} />
            Upload Mach-O File
            <input type="file" className="hidden" onChange={handleFileUpload} />
          </label>
          <div className="flex space-x-2">
            <button
              className={`px-4 py-2 rounded-lg transition-colors ${
                selectedView === "analysis"
                  ? "bg-gray-200"
                  : "hover:bg-gray-100"
              }`}
              onClick={() => setSelectedView("analysis")}
            >
              Analysis
            </button>
            <button
              className={`px-4 py-2 rounded-lg transition-colors ${
                selectedView === "debug" ? "bg-gray-200" : "hover:bg-gray-100"
              }`}
              onClick={() => setSelectedView("debug")}
            >
              Debug Log
            </button>
          </div>
        </div>
      )}

      {/* 
      {isAnalyzing && (
        <div className="p-4 mb-4 bg-blue-50 text-blue-700 rounded-lg flex items-center">
        <div className="flex items-center space-x-4">
          <label className="flex items-center px-4 py-2 bg-blue-500 text-white rounded-lg cursor-pointer hover:bg-blue-600 transition-colors">
            <Upload className="mr-2" size={20} />
            Upload Mach-O File
            <input type="file" className="hidden" onChange={handleFileUpload} />
          </label>
          <div className="flex space-x-2">
            <button
              className={`px-4 py-2 rounded-lg transition-colors ${
                selectedView === "analysis"
                  ? "bg-gray-200"
                  : "hover:bg-gray-100"
              }`}
              onClick={() => setSelectedView("analysis")}
            >
              Analysis
            </button>
            <button
              className={`px-4 py-2 rounded-lg transition-colors ${
                selectedView === "debug" ? "bg-gray-200" : "hover:bg-gray-100"
              }`}
              onClick={() => setSelectedView("debug")}
            >
              Debug Log
            </button>
          </div>
        </div>
      </div> */}

      {isAnalyzing && (
        <div className="p-4 mb-4 bg-blue-50 text-blue-700 rounded-lg flex items-center">
          <div className="animate-spin mr-2">
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              />
            </svg>
          </div>
          Analyzing binary...
        </div>
      )}

      {error && (
        <div className="p-4 mb-4 bg-red-100 text-red-700 rounded-lg flex items-center">
          <XCircle className="mr-2" />
          {error}
        </div>
      )}

      {analysisResult && selectedView === "analysis" && (
        <div className="bg-white mt-8 mb-8 rounded-lg">
          <div className="space-y-6">
            {securityAssessment && (
              <div
                className={`p-4 rounded-lg ${
                  securityAssessment.level === "high"
                    ? "bg-green-50 text-green-700"
                    : securityAssessment.level === "medium"
                    ? "bg-yellow-50 text-yellow-700"
                    : "bg-red-50 text-red-700"
                }`}
              >
                <div className="flex items-center mb-2">
                  <Shield className="mr-2" />
                  <h3 className="text-lg font-medium">Security Assessment</h3>
                </div>
                <p className="mb-2">{securityAssessment.message}</p>
                {securityAssessment.details.length > 0 && (
                  <ul className="list-disc list-inside">
                    {securityAssessment.details.map((detail, i) => (
                      <li key={i}>{detail}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            <div className="border-l-4 border-blue-500 pl-4">
              <h2 className="text-xl font-semibold mb-4 flex items-center">
                <Info className="mr-2" />
                Binary Analysis
              </h2>

              <div className="mb-6">
                <h3 className="text-lg font-medium text-blue-700 mb-2 flex items-center">
                  <FileText className="mr-2" />
                  Header Information
                </h3>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(analysisResult.header).map(
                      ([key, value]) => (
                        <div key={key} className="flex items-center space-x-2">
                          <span className="font-mono text-gray-600">
                            {key}:
                          </span>
                          <span className="font-mono text-blue-600">
                            {String(value)}
                          </span>
                        </div>
                      )
                    )}
                  </div>
                </div>
              </div>
              {analysisResult.uuid && (
                <div className="mb-6">
                  <h3 className="text-lg font-medium text-blue-700 mb-2 flex items-center">
                    <Key className="mr-2" />
                    UUID
                  </h3>
                  <div className="bg-gray-50 p-4 rounded-lg">
                    <span className="font-mono text-blue-600">
                      {analysisResult.uuid}
                    </span>
                  </div>
                </div>
              )}

              {signatureValidation && (
                <div className="mb-6">
                  <h3 className="text-lg font-medium text-blue-700 mb-2 flex items-center">
                    <Lock className="mr-2" />
                    Signature Validation
                  </h3>
                  <div
                    className={`p-4 rounded-lg flex items-center space-x-2 ${
                      signatureValidation.severity === "success"
                        ? "bg-green-50 text-green-700"
                        : signatureValidation.severity === "warning"
                        ? "bg-yellow-50 text-yellow-700"
                        : "bg-red-50 text-red-700"
                    }`}
                  >
                    {signatureValidation.severity === "success" ? (
                      <CheckCircle size={20} />
                    ) : signatureValidation.severity === "warning" ? (
                      <AlertTriangle size={20} />
                    ) : (
                      <XCircle size={20} />
                    )}
                    <span>{signatureValidation.message}</span>
                  </div>

                  <div className="mt-4 bg-gray-50 p-4 rounded-lg">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="flex items-center space-x-2">
                        <Hash className="text-gray-500" size={16} />
                        <span className="font-mono text-gray-600">
                          Hash Algorithm:
                        </span>
                        <span className="font-mono text-blue-600">
                          {signatureValidation.details.hashAlgorithm}
                        </span>
                      </div>

                      <div className="flex items-center space-x-2">
                        <FileCode className="text-gray-500" size={16} />
                        <span className="font-mono text-gray-600">
                          Version:
                        </span>
                        <span className="font-mono text-blue-600">
                          {signatureValidation.details.version}
                        </span>
                      </div>

                      <div className="flex items-center space-x-2">
                        <Server className="text-gray-500" size={16} />
                        <span className="font-mono text-gray-600">
                          Platform:
                        </span>
                        <span className="font-mono text-blue-600">
                          {signatureValidation.details.platform}
                        </span>
                      </div>

                      {signatureValidation.details.teamId && (
                        <div className="flex items-center space-x-2">
                          <Shield className="text-gray-500" size={16} />
                          <span className="font-mono text-gray-600">
                            Team ID:
                          </span>
                          <span className="font-mono text-blue-600">
                            {signatureValidation.details.teamId}
                          </span>
                        </div>
                      )}

                      <div className="flex items-center space-x-2">
                        <Lock className="text-gray-500" size={16} />
                        <span className="font-mono text-gray-600">Sealed:</span>
                        <span className="font-mono text-blue-600">
                          {signatureValidation.details.sealed ? "Yes" : "No"}
                        </span>
                      </div>

                      <div className="flex items-center space-x-2">
                        <Clock className="text-gray-500" size={16} />
                        <span className="font-mono text-gray-600">
                          Timestamped:
                        </span>
                        <span className="font-mono text-blue-600">
                          {signatureValidation.details.timestamped
                            ? "Yes"
                            : "No"}
                        </span>
                      </div>
                    </div>

                    {signatureValidation.details.flags.length > 0 && (
                      <div className="mt-4">
                        <div className="flex items-center space-x-2 mb-2">
                          <Flag className="text-gray-500" size={16} />
                          <span className="font-mono text-gray-600">
                            Flags:
                          </span>
                        </div>
                        <ul className="list-disc list-inside">
                          {signatureValidation.details.flags.map((flag, i) => (
                            <li key={i} className="font-mono text-blue-600">
                              {flag}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {analysisResult.codeSign && (
                <div className="ml-4 space-y-4">
                  <h3 className="text-lg font-medium text-blue-700 flex items-center">
                    <Shield className="mr-2" />
                    Code Signature Details
                  </h3>
                  {analysisResult.codeSign.map((blob: any, i: number) => (
                    <div key={i} className="bg-gray-50 p-4 rounded-lg">
                      <h4 className="font-mono text-gray-700 mb-2">
                        {blob.type}
                      </h4>
                      <div className="grid grid-cols-2 gap-2">
                        {Object.entries(blob.data).map(([key, value]) => (
                          <div
                            key={key}
                            className="flex items-center space-x-2"
                          >
                            <span className="font-mono text-gray-600">
                              {key}:
                            </span>
                            <span className="font-mono text-blue-600">
                              {typeof value === "number"
                                ? "0x" + value.toString(16)
                                : String(value)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="mt-8 ml-4">
                <h3 className="text-lg font-medium text-blue-700 mb-4 flex items-center">
                  <Info className="mr-2" />
                  Debug Log
                </h3>
                <div className="bg-gray-50 p-4 rounded-lg font-mono text-sm space-y-1">
                  {debugLog.map((msg, i) => (
                    <div key={i} className="text-gray-700">
                      {msg}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export { MachoAnalyzer };
