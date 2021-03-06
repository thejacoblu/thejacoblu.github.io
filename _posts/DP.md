Leetcode 96. Unique Binary Search Trees

分析：

对于n，以[1, n]n个数字可以构造几个互不相同的的二叉查找树。

对于序列[1, n]，如果选取数字i作为根节点，那么[1, i-1]在左子树上，[i+1, n]在右子树上。此后可以递归地构造子树。难就难在如何统计可以构造的二叉查找树的数目。

`G(n)`：长度为n的序列的唯一二叉查找树的个数；[1,2,3]构造的查找树个数应该是和[2,3,4]等同等长度的序列构造的二叉查找树的个数是相同的。

`F(i, n)`：以i(1≤i≤n)作为二叉查找树的根。所能构造的二叉查找树个数。
$$
G(n)=F(1,n)+F(2,n)+...+F(n,n)
$$
节点个数为0和1的情况，可以作为起始条件：
$$
G(0)=1,G(1)=1
$$
确定了根之后，所能构造的二叉查找树个数即为左子树的构造个数与右子树的构造个数相乘：
$$
F(i,n)=G(i-1)*G(n-i),1<=i<=n
$$
结合以上，可以得到：
$$
G(n) = G(0)*G(n-1) + G(1)*G(n-2)+...+G(n-1)*G(0)
$$
代码：

