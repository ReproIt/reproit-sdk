use super::*;
use reproit_backend::automatic_replay::resolve_automatic_replay;
use reproit_core::model::{
    LogicalObject, ReplayCapsule, ResolvedDependencyTranscript, ResolvedInteraction,
    ResolvedWorldArtifact, resolve_replay_capsule,
};

type RecordedPair = (Vec<u8>, Vec<u8>);

fn recorded_replay() -> (AutomaticWorldCoordinator, Vec<RecordedPair>) {
    let (sdk, operation_id, _) = started_sdk();
    let mut coordinator = coordinator_with_coverage(sdk, operation_id);
    coordinator.capture_ambient().unwrap();
    let mut records = Vec::new();
    for (index, class) in AutomaticObservationClass::ALL.into_iter().enumerate() {
        records.push(capture(
            &mut coordinator,
            index as u64,
            class,
            None,
            b"target",
            b"recorded",
            AutomaticReplay::first_position(class),
        ));
    }
    let capture = coordinator.close(TriggerCompletion::Return).unwrap();
    let (mut resolved, mut objects) = resolved_vector();
    resolved.trigger.operation_id = operation_id;
    resolved.world = capture.closure.world.clone();
    let mut descriptors = BTreeMap::new();
    for artifact in &capture.closure.artifacts {
        let bytes = fs::read(&artifact.path).unwrap();
        descriptors.insert(
            artifact.object_id,
            LogicalObject {
                media_type: artifact.media_type.clone(),
                object_id: artifact.object_id,
                plain_digest: Digest::of(&bytes),
                plain_size: bytes.len() as u64,
                role: artifact.role,
            },
        );
        objects.insert(artifact.object_id, bytes);
    }
    resolved.world_artifacts = resolved.world.points[0]
        .artifacts
        .iter()
        .map(|reference| {
            let artifact = capture
                .closure
                .artifacts
                .iter()
                .find(|artifact| artifact.uri == reference.uri)
                .unwrap();
            ResolvedWorldArtifact {
                artifact: reference.clone(),
                object: descriptors[&artifact.object_id].clone(),
                point_index: 0,
            }
        })
        .collect();
    let manifest = descriptors
        .values()
        .find(|object| object.media_type == DEPENDENCY_TRANSCRIPT_MEDIA_TYPE)
        .unwrap();
    let transcript: DependencyTranscript =
        canonical::parse_strict(&objects[&manifest.object_id]).unwrap();
    let interactions = transcript
        .interactions
        .iter()
        .map(|interaction| ResolvedInteraction {
            request: descriptors[&interaction.request_object_id].clone(),
            response: descriptors[&interaction.response_object_id].clone(),
        })
        .collect();
    resolved.dependency = Some(ResolvedDependencyTranscript {
        interactions,
        manifest_object: manifest.clone(),
        transcript,
    });
    let replay = resolve_automatic_replay(&resolved, &mut |object| {
        Ok(objects[&object.object_id].clone())
    })
    .unwrap();
    (
        AutomaticWorldCoordinator::new_replay(replay, operation_id).unwrap(),
        records,
    )
}

#[test]
fn captured_observations_replay_through_the_real_session_api() {
    let _process = process_test();
    let (mut replay, records) = recorded_replay();
    for (index, (class, (request, expected))) in AutomaticObservationClass::ALL
        .into_iter()
        .zip(records)
        .enumerate()
    {
        let id = index as u64;
        let position = replay.open_observation(id, class, None).unwrap();
        assert_eq!(position, AutomaticReplay::first_position(class));
        replay.write_observation_request(id, &request).unwrap();
        assert_eq!(
            replay.dispatch_observation(id).unwrap(),
            AutomaticObservationAction::Replay
        );
        let mut response = Vec::new();
        loop {
            let (chunk, complete) = replay.read_observation_response(id).unwrap();
            assert!(chunk.len() <= MAX_AUTOMATIC_OBSERVATION_RESPONSE_READ_BYTES);
            response.extend(chunk);
            if complete {
                break;
            }
        }
        assert_eq!(response, expected);
        replay
            .finish_observation(id, DependencyOutcome::Response, position)
            .unwrap();
    }
    replay.finish_replay().unwrap();
}

#[test]
fn replay_rejects_missing_changed_unread_and_abandoned_observations() {
    let _process = process_test();
    for scenario in [
        "missing",
        "changed",
        "unread",
        "abandoned",
        "unowned",
        "live-response",
    ] {
        let (mut replay, records) = recorded_replay();
        if scenario == "missing" {
            assert!(replay.finish_replay().is_err());
            continue;
        }
        let class = AutomaticObservationClass::Clock;
        let position = replay.open_observation(0, class, None).unwrap();
        if scenario == "changed" {
            replay.write_observation_request(0, b"{}").unwrap();
            assert!(replay.dispatch_observation(0).is_err());
        } else {
            replay.write_observation_request(0, &records[0].0).unwrap();
            replay.dispatch_observation(0).unwrap();
            match scenario {
                "unread" => assert!(
                    replay
                        .finish_observation(0, DependencyOutcome::Response, position)
                        .is_err()
                ),
                "abandoned" => replay.abandon_observation(0).unwrap(),
                "unowned" => assert!(replay.mark_unowned(class, None, b"live effect").is_err()),
                "live-response" => assert!(
                    replay
                        .write_observation_response(0, b"live effect")
                        .is_err()
                ),
                _ => unreachable!(),
            }
        }
        assert!(replay.finish_replay().is_err(), "{scenario}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_replay_accepts_recorded_responses_and_rejects_live_effects() {
    const CHILD: &str = "REPROIT_SDK_NATIVE_REPLAY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // The sentinel traces a whole process. Other test threads must stay outside it.
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "automatic_world::tests::replay::native_replay_accepts_recorded_responses_and_rejects_live_effects", "--nocapture"])
            .env(CHILD, "1")
            .status().unwrap();
        assert!(status.success());
        return;
    }
    for live_effect in [false, true] {
        let (coordinator, records) = recorded_replay();
        let AutomaticWorldMode::Replay(replay) = coordinator.mode else {
            unreachable!()
        };
        let operation = crate::AutomaticReplayOperation::new(replay).unwrap();
        let context = operation.context();
        context.scope_poll(|| {
            for (class, (request, expected)) in
                AutomaticObservationClass::ALL.into_iter().zip(records)
            {
                let mut session = context.open_observation(class, None).unwrap();
                session.write_request(&request).unwrap();
                assert_eq!(session.dispatch().unwrap(), "replay");
                let (response, complete) = session.read_response().unwrap();
                assert!(complete);
                assert_eq!(response, expected);
                session.finish(DependencyOutcome::Response).unwrap();
            }
            if live_effect {
                std::fs::read("/proc/version").unwrap();
            }
        });
        assert_eq!(operation.finish().is_ok(), !live_effect);
    }
}

fn resolved_vector() -> (
    reproit_core::model::ResolvedReplayCapsule,
    BTreeMap<ObjectId, Vec<u8>>,
) {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../.core/specs/v1/managed-capsule-vector.json"
    ))
    .unwrap();
    let capsule: ReplayCapsule =
        serde_json::from_value(vector["capsule"]["value"].clone()).unwrap();
    let mut objects = BTreeMap::new();
    for name in [
        "subject_closure",
        "trigger",
        "failure_payload",
        "world_checkpoint",
        "dependency_transcript",
    ] {
        let bytes = canonical::canonical_bytes(&vector[name]["value"]).unwrap();
        let object = capsule
            .objects
            .iter()
            .find(|object| object.plain_digest == Digest::of(&bytes))
            .unwrap();
        objects.insert(object.object_id, bytes);
    }
    let resolved = resolve_replay_capsule(&capsule, &mut |object| {
        Ok(objects[&object.object_id].clone())
    })
    .unwrap();
    (resolved, objects)
}
