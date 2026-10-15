//
//  OnDeviceAnisetteHelper.swift
//  GetMoreRam
//
//  Uses the same on-device ADI path as SideStore. No Anisette HTTP server is
//  used for authentication: after the ODA libraries are cached, the headers
//  are generated locally by AnisetteKit on the device.
//

import Foundation
import CryptoKit
import Security
import AnisetteKit
import SideSign
import StosSign_Common

final class OnDeviceAnisetteHelper {
    static let shared = OnDeviceAnisetteHelper()

    private let provider = SideSign.AnisetteDataManager.shared
    private let metadataURL = URL(string: "https://zzz.haus/oda.json")!

    private init() {}

    func getAnisetteData() async throws -> StosSign_Common.AnisetteData {
        try convert(await getSideSignAnisetteData())
    }

    func getSideSignAnisetteData() async throws -> SideSign.AnisetteData {
        let identifier = try ensureIdentifier()
        let existingBlob = Keychain.shared.adiPb.flatMap {
            Data(base64Encoded: $0, options: .ignoreUnknownCharacters)
        }

        // AnisetteKit otherwise supplies a constant placeholder local-user ID.
        // Bind LU and device ID to the same bytes used by the ADI provider.
        var identifierBytes = identifier.uuid
        let identifierData = withUnsafeBytes(of: &identifierBytes) { Data($0) }
        let requestHeaders = AnisetteRequestHeaders.defaultHeaders.with {
            $0.clientInfo = AnisetteClientInfo.resolved(fallback: AnisetteClientInfo.onDeviceDefault)
            $0.deviceID = identifier.uuidString.uppercased()
            $0.localUserID = SHA256.hash(data: identifierData)
                .map { String(format: "%02X", $0) }.joined()
        }

        do {
            let result = try await fetch(
                identifier: identifier,
                existingBlob: existingBlob,
                headers: requestHeaders
            )
            if let newBlob = result.newAdiBlob {
                Keychain.shared.adiPb = newBlob.base64EncodedString()
            }
            return result.data
        } catch {
            // Only a confirmed unprovisioned ADI error warrants reprovisioning.
            // Network/parse failures must preserve the existing identity/blob.
            guard existingBlob != nil,
                  let adiError = error as? AnisetteKit.AnisetteError,
                  case .adiError(let code, _) = adiError,
                  code == -45061 else { throw error }
            let result = try await fetch(
                identifier: identifier,
                existingBlob: nil,
                headers: requestHeaders
            )
            if let newBlob = result.newAdiBlob {
                Keychain.shared.adiPb = newBlob.base64EncodedString()
            }
            return result.data
        }
    }

    private func fetch(
        identifier: UUID,
        existingBlob: Data?,
        headers: AnisetteRequestHeaders
    ) async throws -> (data: SideSign.AnisetteData, newAdiBlob: Data?) {
        try await provider.fetchAnisetteData(
            mode: .remoteODA(sourceURL: metadataURL, fallbackURL: metadataURL),
            identifier: identifier,
            existingAdiBlob: existingBlob,
            headers: headers
        )
    }

    private func ensureIdentifier() throws -> UUID {
        if let stored = Keychain.shared.identifier, let uuid = uuid(from: stored) {
            return uuid
        }

        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw NSError(
                domain: "GetMoreRam.OnDeviceAnisette",
                code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "Could not generate Anisette device identifier."]
            )
        }

        let data = Data(bytes)
        Keychain.shared.identifier = data.base64EncodedString()
        guard let uuid = uuid(from: Keychain.shared.identifier!) else {
            throw NSError(
                domain: "GetMoreRam.OnDeviceAnisette",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Generated Anisette identifier is invalid."]
            )
        }
        return uuid
    }

    private func uuid(from value: String) -> UUID? {
        if let uuid = UUID(uuidString: value) {
            return uuid
        }
        guard let data = Data(base64Encoded: value, options: .ignoreUnknownCharacters), data.count == 16 else {
            return nil
        }
        return data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return nil }
            return UUID(uuid: baseAddress.load(as: uuid_t.self))
        }
    }

    func convert(_ data: SideSign.AnisetteData) throws -> StosSign_Common.AnisetteData {
        guard let routingInfo = UInt64(data.routingInfo) else {
            throw NSError(
                domain: "GetMoreRam.OnDeviceAnisette",
                code: -2,
                userInfo: [NSLocalizedDescriptionKey: "Local Anisette returned an invalid routing-info value."]
            )
        }

        let dateFormatter = ISO8601DateFormatter()
        guard let date = dateFormatter.date(from: data.clientTime) else {
            throw NSError(
                domain: "GetMoreRam.OnDeviceAnisette",
                code: -3,
                userInfo: [NSLocalizedDescriptionKey: "Local Anisette returned an invalid client time."]
            )
        }

        return StosSign_Common.AnisetteData(
            machineID: data.machineID,
            oneTimePassword: data.oneTimePassword,
            localUserID: data.localUserID,
            routingInfo: routingInfo,
            deviceUniqueIdentifier: data.deviceID,
            deviceSerialNumber: data.serialNumber,
            deviceDescription: data.clientInfo,
            date: date,
            locale: Locale(identifier: data.locale),
            timeZone: TimeZone(abbreviation: data.timeZone) ?? .current
        )
    }
}
