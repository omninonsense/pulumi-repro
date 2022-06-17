import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";
import * as eks from "@pulumi/eks";
import * as k8s from "@pulumi/kubernetes";

const env = pulumi.getStack();
const config = new pulumi.Config();

const AWS_SSO_ROLE_PREFIX = "/aws-reserved/sso.amazonaws.com";

/**
 * AWS-managed policies used by our EKS nodes
 */
const AWS_POLICY_ARNS: string[] = [
  "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
  "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
  "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
];

export interface KubeArgs extends pulumi.Inputs {
  /**
   * Our Network component. The component wraps a VPC that hosts our Kubernetes
   * cluster
   */
  network: pulumi.Input<Network>;

  /**
   * Tags represents a set of key-value string pairs to which can be applied to
   * an AWS resource.
   */
  tags?: pulumi.Input<aws.Tags>;
}

interface NetworkArgs {
  tags?: pulumi.Input<aws.Tags>;
}

// Network/VPC for our infrastructure
// TODO: Needs polish (maybe)
export class Network extends pulumi.ComponentResource {
  readonly vpc: awsx.ec2.Vpc;

  constructor(name: string, args: NetworkArgs, opts: pulumi.ResourceOptions) {
    super("repro:infra:Network", name, {}, opts);

    this.vpc = new awsx.ec2.Vpc(
      name,
      {
        tags: { name, ...args.tags },
      },
      { parent: this }
    );

    this.registerOutputs({
      vpc: this.vpc,
    });
  }
}

export class KubernetesCluster extends pulumi.ComponentResource {
  /**
   * The EKS cluster resource. This isn't the "physical" EKS cluster, though,
   * but just a wrapper around it. You can access the real cluster at
   * `cluster.eksCluster`
   */
  readonly cluster: eks.Cluster;

  /**
   * The name of the resource (not the EKS cluster itself; you can read that
   * from `cluster.eksCluster.name`)
   */
  readonly name: string;

  /**
   * Contains the location of the kubeconfig file used to execute `kubectl`
   * commands. This ensures the commands run when the context becomes ready
   */
  private nodeGroups: eks.ManagedNodeGroup[];

  constructor(name: string, args: KubeArgs, opts: pulumi.ResourceOptions) {
    super("repro:infra:Kubernetes", name, args, opts);
    this.name = name;
    const network = pulumi.output(args.network);
    const tags = pulumi.output(args.tags ?? {});

    const instanceRole = new aws.iam.Role(
      `${name}-InstanceRole`,
      {
        assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
          Service: "ec2.amazonaws.com",
        }),
      },
      { parent: this }
    );

    AWS_POLICY_ARNS.forEach((policyArn, index) => {
      new aws.iam.RolePolicyAttachment(
        `${name}-rpa-${index}`,
        {
          policyArn,
          role: instanceRole,
        },
        { parent: this }
      );
    });

    const instanceProfile = new aws.iam.InstanceProfile(
      `${name}-instance-profile`,
      { role: instanceRole },
      { parent: this }
    );

    this.cluster = new eks.Cluster(
      name,
      {
        name,
        tags,
        instanceRole,
        version: "1.21",
        vpcId: network.vpc.id,
        publicSubnetIds: network.vpc.publicSubnetIds,
        privateSubnetIds: network.vpc.privateSubnetIds,
        skipDefaultNodeGroup: true,
        createOidcProvider: true,
        providerCredentialOpts: {
          profileName: name,
        },
        nodeGroupOptions: {
          instanceProfile,
          nodeRootVolumeSize: 100,
        },
        roleMappings: [
          pulumi.output(
            this.ssoRoleMapping("AdministratorAccess", "repro:cluster-admin", [
              "repro:cluster-admins",
              "system:masters",
            ])
          ),
          pulumi.output(
            // NOTE: This was granted accidentally. So we might get rid of this in the future
            this.ssoRoleMapping("SystemAdministrator", "repro:developer", [
              "repro:developers",
            ])
          ),
        ],
      },
      { parent: this }
    );

    network.apply(async (network) => {
      let [publicSubnets, privateSubnets] = await Promise.all([
        network.vpc.publicSubnets,
        network.vpc.privateSubnets,
      ]);

      this.addSubnetAutoDiscoveryTags(publicSubnets, "elb");
      this.addSubnetAutoDiscoveryTags(privateSubnets, "internal-elb");
    });

    this.nodeGroups = [
      new eks.ManagedNodeGroup(
        `${name}-ng-1`,
        {
          cluster: this.cluster,
          // TODO: Make configurable
          instanceTypes: [aws.ec2.InstanceType.T3_Medium],
          // TODO: Make configurable
          scalingConfig: {
            minSize: 1,
            desiredSize: 2,
            maxSize: 3,
          },
          diskSize: 100,
          nodeRole: instanceRole,
          // tags: {
          //   "k8s.io/cluster-autoscaler/enabled": "true",
          //   [`k8s.io/cluster-autoscaler/${name}`]: "owned",
          // },
        },
        {
          parent: this.cluster,
          providers: { kubernetes: this.cluster.provider },
        }
      ),
    ];

    /*
			NOTE: This generates the following error (during planning) and exits:
			Diagnostics:
				pulumi:pulumi:Stack (pulumi-repro-dev):
					error: TypeError: Cannot read properties of undefined (reading 'map')
							at /Users/nino/Documents/silicoai/pulumi-repro/node_modules/@pulumi/yaml/yaml.ts:2993:14
							at processTicksAndRejections (node:internal/process/task_queues:95:5)
			*/
    new k8s.yaml.ConfigFile(
      "cert-manager",
      {
        file: "k8s/cert-manager.yaml",
      },
      { provider: this.cluster.provider }
    );

    this.registerOutputs({
      cluster: this.cluster,
      nodeGroups: this.nodeGroups,
    });
  }

  /**
   * Pulumi and EKS take care of _some_ tagging, but it appears they don't tag
   * for common cluster components like auto-scaler or load balancers, etc. So
   * we add our own tagss
   * @param subnets The subnets to tag
   * @param role - is it an internal or public-facing LB?
   */
  private addSubnetAutoDiscoveryTags = (
    subnets: awsx.ec2.Subnet[],
    role: "elb" | "internal-elb"
  ) => {
    subnets.forEach(({ subnetName, id }) => {
      new aws.ec2.Tag(
        `cluster-${subnetName}-shared-tag`,
        {
          resourceId: id,
          key: `kubernetes.io/cluster/${this.name}`,
          value: "shared",
        },
        { parent: this }
      );

      new aws.ec2.Tag(
        `cluster-${subnetName}-role-tag`,
        {
          resourceId: id,
          key: `kubernetes.io/role/${role}`,
          value: "1",
        },
        { parent: this }
      );
    });
  };

  /**
   * Set up RBAC roles inside the cluster. Pulumi takes care of
   * maintaining the `aws-auth` configmap for us through the `eks.Cluster`
   * resource. But we need to create the roles ourself
   */
  setupClusterRbac = () => {
    const { provider } = this.cluster;

    const developerRole = new k8s.rbac.v1.Role(
      `repro-developer-role`,
      {
        metadata: {
          name: "repro:developer",
          namespace: "default",
        },
        rules: [
          {
            apiGroups: ["*"],
            resources: ["*"],
            verbs: ["get", "watch", "list"],
          },
        ],
      },
      { provider, parent: this }
    );

    new k8s.rbac.v1.RoleBinding(
      `repro:developer-role-binding`,
      {
        metadata: {
          name: `repro:developer`,
          namespace: "default",
        },
        subjects: [
          {
            kind: "Group",
            name: "repro:developers",
            apiGroup: "rbac.authorization.k8s.io",
          },
        ],
        roleRef: {
          kind: "Role",
          name: developerRole.metadata.name,
          apiGroup: "rbac.authorization.k8s.io",
        },
      },
      { provider, parent: this }
    );

    new k8s.rbac.v1.ClusterRoleBinding(
      `repro:cluster-admin-cluster-role-binding`,
      {
        metadata: {
          name: `repro:cluster-admin`,
        },
        subjects: [
          {
            kind: "Group",
            name: "repro:admins",
            apiGroup: "rbac.authorization.k8s.io",
          },
        ],
        roleRef: {
          kind: "ClusterRole",
          name: "cluster-admin",
          apiGroup: "rbac.authorization.k8s.io",
        },
      },
      { provider, parent: this }
    );
  };

  /**
   * Looks up a federated role by its canonical name and then strips the path
   * from the ARN. The returned values are used in the kube-system/aws-auth
   * ConfigMap which is used to maps IAM roles to cluster users
   *
   * We're stuck with this function until
   * [kubernetes-sigs/aws-iam-authenticator#416] lands...
   *
   * [kubernetes-sigs/aws-iam-authenticator#416]:
   * https://github.com/kubernetes-sigs/aws-iam-authenticator/pull/416
   *
   */
  private ssoRoleMapping = async (
    ssoRoleName: string,
    usernamePrefix: string,
    groups: string[]
  ): Promise<eks.RoleMapping> => {
    const roles = await aws.iam.getRoles({
      nameRegex: `AWSReservedSSO_${ssoRoleName}_.*`,
      pathPrefix: AWS_SSO_ROLE_PREFIX,
    });

    if (roles.arns.length === 0) {
      throw new pulumi.ResourceError(
        `Could not find an AWS Reserved SSO Role matching ${ssoRoleName}`,
        this
      );
    }

    if (roles.arns.length > 1) {
      const rolesList = roles.arns.join(", ");
      throw new pulumi.ResourceError(
        `Found too many AWS Reserved SSO Role matching ${ssoRoleName}. Not sure which one to select: ${rolesList}`,
        this
      );
    }

    return {
      username: `${usernamePrefix}:{{SessionName}}`,
      groups,
      roleArn: roles.arns[0].replace(AWS_SSO_ROLE_PREFIX, ""),
    };
  };
}

const network = new Network(env, {}, {});
const cluster = new KubernetesCluster(env, { network }, {});
