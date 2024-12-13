/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { omit } from 'lodash';
import moment from 'moment';
import { v4 as uuidv4 } from 'uuid';
import { RoleCredentials } from '@kbn/ftr-common-functional-services';
import {
  ConfigKey,
  EncryptedSyntheticsSavedMonitor,
  MonitorFields,
  PrivateLocation,
} from '@kbn/synthetics-plugin/common/runtime_types';
import { SYNTHETICS_API_URLS } from '@kbn/synthetics-plugin/common/constants';
import expect from '@kbn/expect';
import { secretKeys } from '@kbn/synthetics-plugin/common/constants/monitor_management';
import { SyntheticsMonitorTestService } from '../../../services/synthetics_monitor';
import { omitMonitorKeys } from './create_monitor';
import { DeploymentAgnosticFtrProviderContext } from '../../../ftr_provider_context';
import { PrivateLocationTestService } from '../../../services/synthetics_private_location';
import { getFixtureJson } from './helpers/get_fixture_json';

export default function ({ getService }: DeploymentAgnosticFtrProviderContext) {
  describe('getSyntheticsMonitors', function () {
    const supertest = getService('supertestWithoutAuth');
    const kibanaServer = getService('kibanaServer');
    const retry = getService('retry');
    const samlAuth = getService('samlAuth');
    const monitorTestService = new SyntheticsMonitorTestService(getService);
    const privateLocationTestService = new PrivateLocationTestService(getService);

    let _monitors: MonitorFields[];
    let monitors: MonitorFields[];
    let editorUser: RoleCredentials;
    let privateLocation: PrivateLocation;

    const saveMonitor = async (monitor: MonitorFields, spaceId?: string) => {
      let url = SYNTHETICS_API_URLS.SYNTHETICS_MONITORS + '?internal=true';
      if (spaceId) {
        url = '/s/' + spaceId + url;
      }
      const res = await supertest
        .post(url)
        .set(editorUser.apiKeyHeader)
        .set(samlAuth.getInternalRequestHeader())
        .send(monitor);

      expect(res.status).eql(200, JSON.stringify(res.body));

      return res.body as EncryptedSyntheticsSavedMonitor;
    };

    before(async () => {
      await kibanaServer.savedObjects.cleanStandardList();
      editorUser = await samlAuth.createM2mApiKeyWithRoleScope('editor');
      privateLocation = await privateLocationTestService.addTestPrivateLocation();
      await supertest
        .put(SYNTHETICS_API_URLS.SYNTHETICS_ENABLEMENT)
        .set(editorUser.apiKeyHeader)
        .set(samlAuth.getInternalRequestHeader())
        .expect(200);

      _monitors = [
        getFixtureJson('icmp_monitor'),
        getFixtureJson('tcp_monitor'),
        getFixtureJson('http_monitor'),
        getFixtureJson('browser_monitor'),
      ].map((mon) => ({
        ...mon,
        locations: [privateLocation],
      }));
    });

    beforeEach(() => {
      monitors = _monitors;
    });

    // FLAKY: https://github.com/elastic/kibana/issues/204069
    describe.skip('get many monitors', () => {
      it('without params', async () => {
        const uuid = uuidv4();
        const [mon1, mon2] = await Promise.all(
          monitors.map((mon, i) => saveMonitor({ ...mon, name: `${mon.name}-${uuid}-${i}` }))
        );

        const apiResponse = await supertest
          .get(SYNTHETICS_API_URLS.SYNTHETICS_MONITORS + '?perPage=1000&internal=true') // 1000 to sort of load all saved monitors
          .set(editorUser.apiKeyHeader)
          .set(samlAuth.getInternalRequestHeader())
          .expect(200);

        const found: MonitorFields[] = apiResponse.body.monitors.filter(({ id }: MonitorFields) =>
          [mon1.id, mon2.id].includes(id)
        );
        found.sort(({ id: a }) => (a === mon2.id ? 1 : a === mon1.id ? -1 : 0));
        const foundMonitors = found.map(
          (fields) => fields as unknown as EncryptedSyntheticsSavedMonitor
        );

        const expected = [mon1, mon2];

        /**
         * These dates are dynamically generated by the server, so we can't
         * compare them directly. Instead, we'll just check that they're valid.
         */
        foundMonitors.forEach(({ updated_at: updatedAt, created_at: createdAt }) => {
          expect(moment(createdAt).isValid()).to.be(true);
          expect(moment(updatedAt).isValid()).to.be(true);
        });

        expect(foundMonitors.map((fm) => omit(fm, 'updated_at', 'created_at', 'spaceId'))).eql(
          expected.map((expectedMon) =>
            omit(expectedMon, ['updated_at', 'created_at', ...secretKeys])
          )
        );
      });

      it('with page params', async () => {
        const allMonitors = [...monitors, ...monitors];
        for (const mon of allMonitors) {
          await saveMonitor({ ...mon, name: mon.name + Date.now() });
        }

        await retry.try(async () => {
          const firstPageResp = await supertest
            .get(`${SYNTHETICS_API_URLS.SYNTHETICS_MONITORS}?page=1&perPage=2`)
            .set(editorUser.apiKeyHeader)
            .set(samlAuth.getInternalRequestHeader())
            .expect(200);
          const secondPageResp = await supertest
            .get(`${SYNTHETICS_API_URLS.SYNTHETICS_MONITORS}?page=2&perPage=3`)
            .set(editorUser.apiKeyHeader)
            .set(samlAuth.getInternalRequestHeader())
            .expect(200);

          expect(firstPageResp.body.total).greaterThan(6);
          expect(firstPageResp.body.monitors.length).eql(2);
          expect(secondPageResp.body.monitors.length).eql(3);

          expect(firstPageResp.body.monitors[0].id).not.eql(secondPageResp.body.monitors[0].id);
        });
      });

      it('with single monitorQueryId filter', async () => {
        const uuid = uuidv4();
        const [_, { id: id2 }] = await Promise.all(
          monitors
            .map((mon, i) => ({ ...mon, name: `mon.name-${uuid}-${i}` }))
            .map((mon) => saveMonitor(mon))
        );

        const resp = await supertest
          .get(
            `${SYNTHETICS_API_URLS.SYNTHETICS_MONITORS}?page=1&perPage=10&monitorQueryIds=${id2}`
          )
          .set(editorUser.apiKeyHeader)
          .set(samlAuth.getInternalRequestHeader())
          .expect(200);

        const resultMonitorIds = resp.body.monitors.map(({ id }: Partial<MonitorFields>) => id);
        expect(resultMonitorIds.length).eql(1);
        expect(resultMonitorIds).eql([id2]);
      });

      it('with multiple monitorQueryId filter', async () => {
        const uuid = uuidv4();
        const [_, { id: id2 }, { id: id3 }] = await Promise.all(
          monitors
            .map((mon, i) => ({ ...mon, name: `${mon.name}-${uuid}-${i}` }))
            .map((monT) => saveMonitor(monT))
        );

        const resp = await supertest
          .get(
            `${SYNTHETICS_API_URLS.SYNTHETICS_MONITORS}?page=1&perPage=10&sortField=name.keyword&sortOrder=asc&monitorQueryIds=${id2}&monitorQueryIds=${id3}`
          )
          .set(editorUser.apiKeyHeader)
          .set(samlAuth.getInternalRequestHeader())
          .expect(200);

        const resultMonitorIds = resp.body.monitors.map(({ id }: Partial<MonitorFields>) => id);

        expect(resultMonitorIds.length).eql(2);
        expect(resultMonitorIds).eql([id2, id3]);
      });

      it('monitorQueryId respects custom_heartbeat_id while filtering', async () => {
        const customHeartbeatId0 = 'custom-heartbeat-id-test-01';
        const customHeartbeatId1 = 'custom-heartbeat-id-test-02';
        await Promise.all(
          [
            {
              ...monitors[0],
              [ConfigKey.CUSTOM_HEARTBEAT_ID]: customHeartbeatId0,
              [ConfigKey.NAME]: `NAME-${customHeartbeatId0}`,
            },
            {
              ...monitors[1],
              [ConfigKey.CUSTOM_HEARTBEAT_ID]: customHeartbeatId1,
              [ConfigKey.NAME]: `NAME-${customHeartbeatId1}`,
            },
          ].map((monT) => saveMonitor(monT))
        );

        const resp = await supertest
          .get(
            `${SYNTHETICS_API_URLS.SYNTHETICS_MONITORS}?page=1&perPage=10&sortField=name.keyword&sortOrder=asc&monitorQueryIds=${customHeartbeatId0}&monitorQueryIds=${customHeartbeatId1}`
          )
          .set(editorUser.apiKeyHeader)
          .set(samlAuth.getInternalRequestHeader())
          .expect(200);

        const resultMonitorIds = resp.body.monitors
          .map(({ id }: Partial<MonitorFields>) => id)
          .filter((id: string, index: number, arr: string[]) => arr.indexOf(id) === index); // Filter only unique
        expect(resultMonitorIds.length).eql(2);
        expect(resultMonitorIds).eql([customHeartbeatId0, customHeartbeatId1]);
      });

      it('gets monitors from all spaces', async () => {
        const SPACE_ID = `test-space-${uuidv4()}`;
        const SPACE_NAME = `test-space-name ${uuidv4()}`;
        await kibanaServer.spaces.create({ id: SPACE_ID, name: SPACE_NAME });
        const spaceScopedPrivateLocation = await privateLocationTestService.addTestPrivateLocation(
          SPACE_ID
        );

        const allMonitors = [...monitors, ...monitors];
        for (const mon of allMonitors) {
          await saveMonitor(
            { ...mon, name: mon.name + Date.now(), locations: [spaceScopedPrivateLocation] },
            SPACE_ID
          );
        }

        const firstPageResp = await supertest
          .get(`${SYNTHETICS_API_URLS.SYNTHETICS_MONITORS}?page=1&perPage=1000`)
          .set(editorUser.apiKeyHeader)
          .set(samlAuth.getInternalRequestHeader())
          .expect(200);
        const defaultSpaceMons = firstPageResp.body.monitors.filter(
          ({ spaceId }: { spaceId: string }) => spaceId === 'default'
        );
        const testSpaceMons = firstPageResp.body.monitors.filter(
          ({ spaceId }: { spaceId: string }) => spaceId === SPACE_ID
        );

        expect(defaultSpaceMons.length).to.eql(22);
        expect(testSpaceMons.length).to.eql(0);

        const res = await supertest
          .get(
            `${SYNTHETICS_API_URLS.SYNTHETICS_MONITORS}?page=1&perPage=1000&showFromAllSpaces=true`
          )
          .set(editorUser.apiKeyHeader)
          .set(samlAuth.getInternalRequestHeader())
          .expect(200);

        const defaultSpaceMons1 = res.body.monitors.filter(
          ({ spaceId }: { spaceId: string }) => spaceId === 'default'
        );
        const testSpaceMons1 = res.body.monitors.filter(
          ({ spaceId }: { spaceId: string }) => spaceId === SPACE_ID
        );

        expect(defaultSpaceMons1.length).to.eql(22);
        expect(testSpaceMons1.length).to.eql(8);
      });
    });

    describe('get one monitor', () => {
      it('should get by id', async () => {
        const uuid = uuidv4();
        const [{ id: id1 }] = await Promise.all(
          monitors
            .map((mon, i) => ({ ...mon, name: `${mon.name}-${uuid}-${i}` }))
            .map((monT) => saveMonitor(monT))
        );

        const apiResponse = await monitorTestService.getMonitor(id1, { user: editorUser });

        expect(apiResponse.body).eql(
          omitMonitorKeys({
            ...monitors[0],
            [ConfigKey.MONITOR_QUERY_ID]: apiResponse.body.id,
            [ConfigKey.CONFIG_ID]: apiResponse.body.id,
            revision: 1,
            locations: [privateLocation],
            name: `${monitors[0].name}-${uuid}-0`,
          })
        );
      });

      it('should get by id with ui query param', async () => {
        const uuid = uuidv4();
        const [{ id: id1 }] = await Promise.all(
          monitors
            .map((mon, i) => ({ ...mon, name: `${mon.name}-${uuid}-${i}` }))
            .map((monT) => saveMonitor(monT))
        );

        const apiResponse = await monitorTestService.getMonitor(id1, {
          internal: true,
          user: editorUser,
        });

        expect(apiResponse.body).eql(
          omit(
            {
              ...monitors[0],
              form_monitor_type: 'icmp',
              revision: 1,
              locations: [privateLocation],
              name: `${monitors[0].name}-${uuid}-0`,
              hosts: '192.33.22.111:3333',
              hash: '',
              journey_id: '',
              max_attempts: 2,
              labels: {},
            },
            ['config_id', 'id', 'form_monitor_type']
          )
        );
      });

      it('returns 404 if monitor id is not found', async () => {
        const invalidMonitorId = 'invalid-id';
        const expected404Message = `Monitor id ${invalidMonitorId} not found!`;

        const getResponse = await supertest
          .get(SYNTHETICS_API_URLS.GET_SYNTHETICS_MONITOR.replace('{monitorId}', invalidMonitorId))
          .set(editorUser.apiKeyHeader)
          .set(samlAuth.getInternalRequestHeader())
          .expect(404);

        expect(getResponse.body.message).eql(expected404Message);
      });

      it('validates param length', async () => {
        const veryLargeMonId = new Array(1050).fill('1').join('');

        await supertest
          .get(SYNTHETICS_API_URLS.GET_SYNTHETICS_MONITOR.replace('{monitorId}', veryLargeMonId))
          .set(editorUser.apiKeyHeader)
          .set(samlAuth.getInternalRequestHeader())
          .expect(400);
      });
    });
  });
}
