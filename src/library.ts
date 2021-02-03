import {createHash, createHmac} from 'crypto'
import {formatRFC7231} from 'date-fns'
import got, {Response} from 'got'

const nconf: typeof import('nconf') = require.main.require('nconf')
const winston: typeof import('winston') = require.main.require('winston')

let request = got

export async function init(): Promise<void> {
  const accessId = nconf.get('aliGreenConfig:ACCESS_KEY_ID')
  const accessSecret = nconf.get('aliGreenConfig:SECRET_ACCESS_KEY')
  request = got.extend({
    url: `http://green.cn-${nconf.get('aliGreenConfig:REGION')}.aliyuncs.com/green/text/scan`,
    responseType: 'json',
    headers: {
      'x-acs-version': '2018-05-09',
      'x-acs-signature-version': '1.0',
      'x-acs-signature-method': 'HMAC-SHA1',
    },
    hooks: {
      beforeRequest: [(options) => {
        const date = formatRFC7231(new Date())
        const body = JSON.stringify(options.json)
        const md5 = createHash('md5').update(body).digest('base64')
        options.headers['content-md5'] = md5
        options.headers['x-acs-signature-nonce'] = Math.random().toString(36)
        options.headers['date'] = date

        const acsHeaders = Object.keys(options.headers).filter((k) => k.startsWith('x-acs-')).sort()

        const strs: string[] = [options.method, 'application/json', md5, 'application/json', date,
          ...acsHeaders.map((header) => `${header}:${options.headers[header]}`), options.url.pathname]
        const str = strs.join('\n')
        const signature = createHmac('sha1', accessSecret).update(str).digest('base64')
        options.headers['authorization'] = `acs ${accessId}:${signature}`
      }],
    },
  })
}

interface IOnPostData {
  post: {
    content: string
  }
  data: Record<string, unknown>
}

interface IAliyunResponse<T> {
  code: number
  msg: string
  requestId: string
  data: T
}

interface IGreenTextResponse {
  code: number
  msg: string
  dataId: string
  taskId: string
  content: string
  filteredContent: string
  results: {
    scene: string
    suggestion: string
    label: string
    rate: number
    extras: Record<string, unknown>
    details: {
      label: string
      contexts: {
        context: string
        positions: {startPos: number; endPos: number}[]
        libName: string
        libCode: string
        ruleTYpe: string
      }[]
      hintWords: [{context: string}]
    }[]
  }[]
}

type GreenTextResponse = IAliyunResponse<IGreenTextResponse[]>

export async function onPost(data: IOnPostData): Promise<IOnPostData> {
  const content = data.post.content
  await check(content)
  return data
}

interface IOnTopicData {
  title: string
  content: string
}

export async function onTopicPost<T extends IOnTopicData>(data:T): Promise<T> {
  await Promise.all([
    check(data.title),
    check(data.content),
  ])
  return data
}

async function check(content: string): Promise<GreenTextResponse> {
  let res: Response<GreenTextResponse>
  try {
    res = await request.post<GreenTextResponse>({
      json: {
        bizType: 'bbs',
        scenes: ['antispam'],
        tasks: [{content}],
      },
    })
    winston.debug(res.body)
  } catch (e) {
    winston.error(e)
    throw new Error('[[green:scan_fail]]')
  }
  if (res.body.data[0].results.some((e) => e.suggestion !== 'pass')) {
    throw new Error('[[green:illegal_content]]')
  }
  return res.body
}

interface IUserUpdateProfileData {
  uid: number
  data: Record<string, string>
  fields: string[]
}
export async function onUserUpdateProfile<T extends IUserUpdateProfileData>(data: T): Promise<T> {
  const checkFields = ['username', 'signature', 'aboutme', 'location', 'fullname']
  for (const field of checkFields) {
    if (!data.data[field]) continue
    await check(data.data[field])
  }

  return data
}
