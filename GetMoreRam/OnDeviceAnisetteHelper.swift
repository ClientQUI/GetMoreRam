//
//  OnDeviceAnisetteHelper.swift
//  GetMoreRam
//
//  Uses the same on-device ADI path as SideStore. No Anisette HTTP server is
//  used for authentication: after the ODA libraries are cached, the headers
//  are generated locally by AnisetteKit on the device.
//

import Foundation
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
        let identifier = try ensureIdentifier()
        let existingBlob = Keychain.shared.adiPb.flatMap {
            Data(base64Encoded: $0, options: .ignoreUnknownCharacters)
        }

        let requestHeaders = AnisetteRequestHeaders().with {
            // This is the client profile that works with the current GSA flow
            // in SideStore. Keep it configurable in one place for future Apple
            // changes instead of querying a remote /v3/client_info endpoint.
            $0.clientInfo = "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
            $0.userAgent = "AuthKit/1 (Android; Android 14) (com.apple.akd/1.0)"
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
            return try convert(result.data)
        } catch {
            // A blob provisioned by an older/remote provider can be rejected by
            // the local provider. Discard it once and let AnisetteKit provision
            // a fresh local blob before returning the original error.
            guard existingBlob != nil else { throw error }
            Keychain.shared.adiPb = nil
            let result = try await fetch(
                identifier: identifier,
                existingBlob: nil,
                headers: requestHeaders
            )
            if let newBlob = result.newAdiBlob {
                Keychain.shared.adiPb = newBlob.base64EncodedString()
            }
            return try convert(result.data)
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

    private func convert(_ data: SideSign.AnisetteData) throws -> StosSign_Common.AnisetteData {
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
