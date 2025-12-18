//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
@testable import SignalServiceKit
import GRDB
import LibSignalClient

class DeliveryReceiptInvalidMessageTest: SSKBaseTest {
    
    let localE164Identifier = "+13235551234"
    let localAci = Aci.randomForTesting()
    
    let attackerE164Identifier = "+14159671337"
    var attackerClient: TestSignalClient!
    
    private lazy var localClient = LocalSignalClient()
    let runner = TestProtocolRunner()
    lazy var fakeService = FakeService(localClient: localClient, runner: runner)
    
    var receiptSender: MockReceiptSender!
    
    // MARK: - Setup
    
    override func setUp() {
        super.setUp()
        
        // Setup mock receipt sender to track delivery receipts
        receiptSender = MockReceiptSender()
        
        // Replace the real receipt sender with our mock
        SSKEnvironment.shared.receiptSenderRef = receiptSender
        
        // Register local client
        let identityManager = DependenciesBridge.shared.identityManager
        identityManager.generateAndPersistNewIdentityKey(for: .aci)
        identityManager.generateAndPersistNewIdentityKey(for: .pni)
        SSKEnvironment.shared.databaseStorageRef.write { tx in
            (DependenciesBridge.shared.registrationStateChangeManager as! RegistrationStateChangeManagerImpl).registerForTests(
                localIdentifiers: .init(
                    aci: localAci,
                    pni: Pni.randomForTesting(),
                    e164: .init(localE164Identifier)!
                ),
                tx: tx
            )
            
            DependenciesBridge.shared.tsAccountManager.setRegistrationId(RegistrationIdGenerator.generate(), for: .aci, tx: tx)
            DependenciesBridge.shared.tsAccountManager.setRegistrationId(RegistrationIdGenerator.generate(), for: .pni, tx: tx)
        }
        
        // Setup attacker client
        attackerClient = FakeSignalClient.generate(e164Identifier: attackerE164Identifier)
        
        write { transaction in
            try! self.runner.initialize(senderClient: self.attackerClient,
                                        recipientClient: self.localClient,
                                        transaction: transaction)
        }
    }
    
    override func tearDown() {
        try! SSKEnvironment.shared.databaseStorageRef.grdbStorage.testing_tearDownDatabaseChangeObserver()
        super.tearDown()
    }
    
    // MARK: - Tests for Reaction Attack
    
    func testReactionToNonExistentMessage_ShouldNotSendDeliveryReceipt() {
        // 1. Attacker sends reaction to a non-existent message
        // 2. Victim's device shoudl suppresse delivery receipt
        
        let expectMessageProcessed = expectation(description: "message processed")
        let expectFlushNotification = expectation(description: "queue flushed")
        
        NotificationCenter.default.observe(once: MessageProcessor.messageProcessorDidDrainQueue).done { _ in
            expectFlushNotification.fulfill()
        }
        
        // Create a reaction to a non-existent message (timestamp from yesterday)
        let fakeMessageTimestamp = UInt64(Date().timeIntervalSince1970 - 86400) * 1000
        let reactionEmoji = "❤️"
        
        let dataMessageBuilder = SSKProtoDataMessage.builder()
        
        // Build reaction to non-existent message
        let reactionBuilder = SSKProtoDataMessageReaction.builder()
        reactionBuilder.setEmoji(reactionEmoji)
        reactionBuilder.setTimestamp(fakeMessageTimestamp)
        reactionBuilder.setTargetAuthorAci(localAci.serviceIdString)
        reactionBuilder.setRemove(false)
        
        dataMessageBuilder.setReaction(try! reactionBuilder.build())
        dataMessageBuilder.setTimestamp(NSDate.ows_millisecondTimeStamp())
        
        // Send the malicious reaction
        let contentBuilder = SSKProtoContent.builder()
        contentBuilder.setDataMessage(try! dataMessageBuilder.build())
        let contentData = try! contentBuilder.buildSerializedData()
        
        let envelopeBuilder = SSKProtoEnvelope.builder(timestamp: NSDate.ows_millisecondTimeStamp())
        envelopeBuilder.setSourceServiceID(attackerClient.serviceId.serviceIdString)
        envelopeBuilder.setSourceDevice(attackerClient.deviceId)
        envelopeBuilder.setServerTimestamp(NSDate.ows_millisecondTimeStamp())
        envelopeBuilder.setServerGuidBinary(UUID().data)
        envelopeBuilder.setType(.unidentifiedSender)
        
        // Encrypt the content
        let ciphertext = write { transaction in
            try! runner.encrypt(
                contentData,
                senderClient: attackerClient,
                recipientClient: localClient,
                transaction: transaction
            )
        }
        envelopeBuilder.setContent(Data(ciphertext.serialize()))
        
        let envelopeData = try! envelopeBuilder.buildSerializedData()
        
        // Reset receipt tracking before processing
        receiptSender.enqueuedReceipts.removeAll()
        
        // Process the malicious message
        SSKEnvironment.shared.messageProcessorRef.enqueueReceivedEnvelopeData(
            envelopeData,
            serverDeliveryTimestamp: NSDate.ows_millisecondTimeStamp(),
            envelopeSource: .tests
        ) {}
        
        // Small delay to allow processing
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            expectMessageProcessed.fulfill()
        }
        
        waitForExpectations(timeout: 2.0)
        
        // No delivery receipt should be sent for invalid reaction
        XCTAssertEqual(receiptSender.enqueuedReceipts.count, 0, "Delivery receipt was sent for reaction to non-existent message")
    }
    
    func testReactionToExistingMessage_ShouldSendDeliveryReceipt() {
        // This test verifies that legitimate reactions still send delivery receipts
        
        let expectMessageProcessed = expectation(description: "message processed")
        let expectFlushNotification = expectation(description: "queue flushed")
        
        NotificationCenter.default.observe(once: MessageProcessor.messageProcessorDidDrainQueue).done { _ in
            expectFlushNotification.fulfill()
        }
        
        // First, send a real message from attacker to local user
        let realMessageTimestamp = NSDate.ows_millisecondTimeStamp()
        let messageBuilder = SSKProtoDataMessage.builder()
        messageBuilder.setBody("Hello")
        messageBuilder.setTimestamp(realMessageTimestamp)
        
        let contentBuilder = SSKProtoContent.builder()
        contentBuilder.setDataMessage(try! messageBuilder.build())
        let contentData = try! contentBuilder.buildSerializedData()
        
        let envelopeBuilder = SSKProtoEnvelope.builder(timestamp: realMessageTimestamp)
        envelopeBuilder.setSourceServiceID(attackerClient.serviceId.serviceIdString)
        envelopeBuilder.setSourceDevice(attackerClient.deviceId)
        envelopeBuilder.setServerTimestamp(NSDate.ows_millisecondTimeStamp())
        envelopeBuilder.setServerGuidBinary(UUID().data)
        envelopeBuilder.setType(.unidentifiedSender)
        
        let ciphertext1 = write { transaction in
            try! runner.encrypt(
                contentData,
                senderClient: attackerClient,
                recipientClient: localClient,
                transaction: transaction
            )
        }
        envelopeBuilder.setContent(Data(ciphertext1.serialize()))
        
        let envelopeData1 = try! envelopeBuilder.buildSerializedData()
        
        SSKEnvironment.shared.messageProcessorRef.enqueueReceivedEnvelopeData(
            envelopeData1,
            serverDeliveryTimestamp: NSDate.ows_millisecondTimeStamp(),
            envelopeSource: .tests
        ) {}
        
        // Wait for first message to be processed
        Thread.sleep(forTimeInterval: 0.5)
        
        // Now send a reaction to that existing message
        let reactionBuilder = SSKProtoDataMessageReaction.builder()
        reactionBuilder.setEmoji("👍")
        reactionBuilder.setTimestamp(realMessageTimestamp)
        reactionBuilder.setTargetAuthorAci(attackerClient.serviceId.serviceIdString)
        reactionBuilder.setRemove(false)
        
        let dataMessageBuilder2 = SSKProtoDataMessage.builder()
        dataMessageBuilder2.setReaction(try! reactionBuilder.build())
        dataMessageBuilder2.setTimestamp(NSDate.ows_millisecondTimeStamp())
        
        let contentBuilder2 = SSKProtoContent.builder()
        contentBuilder2.setDataMessage(try! dataMessageBuilder2.build())
        let contentData2 = try! contentBuilder2.buildSerializedData()
        
        let envelopeBuilder2 = SSKProtoEnvelope.builder(timestamp: NSDate.ows_millisecondTimeStamp())
        envelopeBuilder2.setSourceServiceID(attackerClient.serviceId.serviceIdString)
        envelopeBuilder2.setSourceDevice(attackerClient.deviceId)
        envelopeBuilder2.setServerTimestamp(NSDate.ows_millisecondTimeStamp())
        envelopeBuilder2.setServerGuidBinary(UUID().data)
        envelopeBuilder2.setType(.unidentifiedSender)
        
        let ciphertext2 = write { transaction in
            try! runner.encrypt(
                contentData2,
                senderClient: attackerClient,
                recipientClient: localClient,
                transaction: transaction
            )
        }
        envelopeBuilder2.setContent(Data(ciphertext2.serialize()))
        
        let envelopeData2 = try! envelopeBuilder2.buildSerializedData()
        
        // Reset receipt tracking before sending reaction
        receiptSender.enqueuedReceipts.removeAll()
        
        SSKEnvironment.shared.messageProcessorRef.enqueueReceivedEnvelopeData(
            envelopeData2,
            serverDeliveryTimestamp: NSDate.ows_millisecondTimeStamp(),
            envelopeSource: .tests
        ) {}
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            expectMessageProcessed.fulfill()
        }
        
        waitForExpectations(timeout: 3.0)
        
        // Delivery receipt SHOULD be sent for valid reaction
        XCTAssertGreaterThan(receiptSender.enqueuedReceipts.count, 0,
                            "Delivery receipt should be sent for reaction to existing message")
    }
    
    // MARK: - Tests for Delete Attack
    
    func testDeleteOfNonExistentMessage_ShouldNotSendDeliveryReceipt() {
        // Similar to reaction test, but for delete messages
        
        let expectMessageProcessed = expectation(description: "message processed")
        let expectFlushNotification = expectation(description: "queue flushed")
        
        NotificationCenter.default.observe(once: MessageProcessor.messageProcessorDidDrainQueue).done { _ in
            expectFlushNotification.fulfill()
        }
        
        // Create a delete for a non-existent message
        let fakeMessageTimestamp = UInt64(Date().timeIntervalSince1970 - 86400) * 1000
        
        let deleteBuilder = SSKProtoDataMessageDelete.builder(targetSentTimestamp: fakeMessageTimestamp)
        
        let dataMessageBuilder = SSKProtoDataMessage.builder()
        dataMessageBuilder.setDelete(try! deleteBuilder.build())
        dataMessageBuilder.setTimestamp(NSDate.ows_millisecondTimeStamp())
        
        let contentBuilder = SSKProtoContent.builder()
        contentBuilder.setDataMessage(try! dataMessageBuilder.build())
        let contentData = try! contentBuilder.buildSerializedData()
        
        let envelopeBuilder = SSKProtoEnvelope.builder(timestamp: NSDate.ows_millisecondTimeStamp())
        envelopeBuilder.setSourceServiceID(attackerClient.serviceId.serviceIdString)
        envelopeBuilder.setSourceDevice(attackerClient.deviceId)
        envelopeBuilder.setServerTimestamp(NSDate.ows_millisecondTimeStamp())
        envelopeBuilder.setServerGuidBinary(UUID().data)
        envelopeBuilder.setType(.unidentifiedSender)
        
        let ciphertext = write { transaction in
            try! runner.encrypt(
                contentData,
                senderClient: attackerClient,
                recipientClient: localClient,
                transaction: transaction
            )
        }
        envelopeBuilder.setContent(Data(ciphertext.serialize()))
        
        let envelopeData = try! envelopeBuilder.buildSerializedData()
        
        receiptSender.enqueuedReceipts.removeAll()
        
        SSKEnvironment.shared.messageProcessorRef.enqueueReceivedEnvelopeData(
            envelopeData,
            serverDeliveryTimestamp: NSDate.ows_millisecondTimeStamp(),
            envelopeSource: .tests
        ) {}
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            expectMessageProcessed.fulfill()
        }
        
        waitForExpectations(timeout: 2.0)
        
        // No delivery receipt for invalid delete
        XCTAssertEqual(receiptSender.enqueuedReceipts.count, 0,
                      "Delivery receipt was sent for delete of non-existent message")
    }
}

// MARK: - Mock Receipt Sender

/// Mock receipt sender that tracks all enqueued receipts for testing
class MockReceiptSender: ReceiptSender {
    var enqueuedReceipts: [(aci: Aci, timestamp: UInt64)] = []
    
    override func enqueueDeliveryReceipt(
        for decryptedEnvelope: DecryptedIncomingEnvelope,
        messageUniqueId: String?,
        tx: DBWriteTransaction
    ) {
        enqueuedReceipts.append((aci: decryptedEnvelope.sourceAci, timestamp: decryptedEnvelope.timestamp))
        super.enqueueDeliveryReceipt(for: decryptedEnvelope, messageUniqueId: messageUniqueId, tx: tx)
    }
}
