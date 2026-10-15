//
//  LoginViewModel.swift
//  GetMoreRam
//
//  Created by s s on 2025/3/15.
//
import SwiftUI
import StosSign_API
import StosSign_Auth
import StosSign_Common
import class SideSign.DeveloperPortal
import enum SideSign.TwoFactorRequest
import enum SideSign.TwoFactorResponse

@MainActor
class LoginViewModel: ObservableObject {
    @Published var appleID = ""
    @Published var password = ""
    @Published var needVerificationCode = false
    @Published var verificationCode = ""
    @Published var loginModalShow = false
    @Published var teamSelectionShow = false
    @Published var isLoginInProgress = false
    @Published private(set) var isVerificationCodeSubmitting = false
    @Published var logs = ""
    @Published var availableTeams: [Team] = []
    
    private var verificationCodeHandler: ((String?) -> Void)?
    private var isAuthenticationCancellationRequested = false
    
    func submitVerificationCode() {
        guard !isVerificationCodeSubmitting,
              let verificationCodeHandler else { return }

        self.verificationCodeHandler = nil
        isVerificationCodeSubmitting = true
        verificationCodeHandler(verificationCode)
    }

    func cancelAuthentication() {
        guard isLoginInProgress else { return }

        isAuthenticationCancellationRequested = true

        let verificationCodeHandler = verificationCodeHandler
        self.verificationCodeHandler = nil
        needVerificationCode = false
        verificationCode = ""
        isVerificationCodeSubmitting = false

        verificationCodeHandler?(nil)
    }
    
    func authenticate() async throws -> Bool {
        if isLoginInProgress {
            return false
        }
        
        logs = ""
        isLoginInProgress = true
        isAuthenticationCancellationRequested = false
        
        func logging(text: String) {
            Task { @MainActor [weak self] in
                self?.logs.append("\(text)\n")
            }
        }
        
        AnisetteDataHelper.shared.loggingFunc = logging

        defer {
            verificationCodeHandler = nil
            appleID = ""
            password = ""
            needVerificationCode = false
            verificationCode = ""
            isLoginInProgress = false
            isVerificationCodeSubmitting = false
            isAuthenticationCancellationRequested = false
        }

        do {
            let account: Account
            let session: AppleAPISession
            var sideSignTeams: [Team]?
            if UserDefaults.standard.object(forKey: "UseOnDeviceAnisette") == nil ||
                UserDefaults.standard.bool(forKey: "UseOnDeviceAnisette") {
                let anisette = try await OnDeviceAnisetteHelper.shared.getSideSignAnisetteData()
                let portal = DeveloperPortal()
                let result = try await portal.authenticate(
                    appleID: appleID, password: password, anisetteData: anisette,
                    xcodeVersion: "27.0 (27A5218g)",
                    accountRepairHandler: { _, _ in .cancel },
                    verificationHandler: { [weak self] request in
                        guard let self else { return .cancel }
                        return await self.handleSideSignVerification(request)
                    })
                // Keep StosSign's types for the existing App ID/signing UI only.
                guard let personID = Int(result.account.identifier) else {
                    throw "SideSign returned an unsupported account identifier."
                }
                let accountData = try JSONSerialization.data(withJSONObject: [
                    "email": result.account.appleID,
                    "personId": personID,
                    "dsFirstName": result.account.firstName,
                    "dsLastName": result.account.lastName
                ])
                account = try JSONDecoder().decode(Account.self, from: accountData)
                session = AppleAPISession(dsid: result.session.dsid, authToken: result.session.authToken,
                    anisetteData: try OnDeviceAnisetteHelper.shared.convert(result.session.anisetteData))
                sideSignTeams = try await portal.fetchTeams(for: result.account, session: result.session).map { team in
                    let type: TeamType
                    switch team.type {
                    case .free: type = .free
                    case .individual: type = .individual
                    case .organization: type = .organization
                    case .unknown: type = .unknown
                    }
                    return Team(name: team.name, identifier: team.identifier, type: type, account: account)
                }
            } else {
                let anisetteData = try await AnisetteDataHelper.shared.getAnisetteData()
                (account, session) = try await AppleAPI.shared.authenticate(appleID: appleID, password: password, anisetteData: anisetteData) { [weak self] completionHandler in
                    guard let self else {
                        completionHandler(nil)
                        return
                    }

                    self.prepareForVerification(using: completionHandler)
                }
            }

            guard !isAuthenticationCancellationRequested else {
                throw CancellationError()
            }

            logging(text: "Successfully signed in")

            DataManager.shared.model.account = account
            DataManager.shared.model.session = session
            Keychain.shared.appleIDEmailAddress = appleID
            Keychain.shared.appleIDPassword = password

            let teams: [Team]
            if let sideSignTeams {
                teams = sideSignTeams
            } else {
                teams = try await fetchTeams(for: account, session: session)
            }
            guard !teams.isEmpty else { throw "Unable to Fetch Team!" }
            logging(text: "Successfully fetched teams")
            availableTeams = teams

            return true
        } catch {
            if isAuthenticationCancellationRequested {
                throw CancellationError()
            }
            throw error
        }
    }

    private func prepareForVerification(using handler: @escaping (String?) -> Void) {
        guard !isAuthenticationCancellationRequested else {
            handler(nil)
            return
        }

        verificationCodeHandler = handler
        verificationCode = ""
        needVerificationCode = true
        isVerificationCodeSubmitting = false
    }

    private func handleSideSignVerification(_ request: TwoFactorRequest) async -> TwoFactorResponse {
        guard !isAuthenticationCancellationRequested else { return .cancel }
        switch request {
        case .selectDeliveryMethod(let preferred, let phones):
            if preferred == .sms, let phone = phones.first {
                return .requestSMS(phoneID: phone.id)
            }
            return .requestTrustedDevice
        case .trustedDevice, .sms, .voice:
            if let error = request.error { logs.append("\(error)\n") }
            let code: String? = await withCheckedContinuation { continuation in
                prepareForVerification { continuation.resume(returning: $0) }
            }
            guard let code, !isAuthenticationCancellationRequested else { return .cancel }
            return .verificationCode(code.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
    
    func fetchTeams(for account: Account, session: AppleAPISession) async throws -> [Team]
    {

        let fetchedTeams = try await AppleAPI.shared.fetchTeamsForAccount(account: account, session: session)
        guard !fetchedTeams.isEmpty else {
            throw "Unable to Fetch Team!"
        }
        
        return fetchedTeams
    }
}
